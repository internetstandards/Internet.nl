import binascii
import concurrent.futures
from binascii import hexlify
from enum import Enum
from pathlib import Path
import socket
from ssl import match_hostname, CertificateError
from typing import Any, Dict, Generator, List, Optional, Tuple

import subprocess
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives._serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.x509 import Certificate
from django.conf import settings
from dns.name import EmptyLabel
from dns.resolver import NXDOMAIN, NoAnswer, NoNameservers, LifetimeTimeout
from nassl._nassl import OpenSSLError
from nassl.ephemeral_key_info import OpenSslEvpPkeyEnum
from nassl.ssl_client import ClientCertificateRequested, OpenSslDigestNidEnum
from sslyze import (
    ScanCommand,
    ServerScanRequest,
    ServerNetworkLocation,
    ServerNetworkConfiguration,
    ProtocolWithOpportunisticTlsEnum,
    ScanCommandsExtraArguments,
    CertificateInfoExtraArgument,
    Scanner,
    ServerScanStatusEnum,
    ServerScanResult,
    TlsVersionEnum,
    CipherSuite,
    ServerTlsProbingResult,
    ClientAuthRequirementEnum,
    SessionRenegotiationExtraArgument,
)

from sslyze.errors import (
    ServerRejectedTlsHandshake,
    TlsHandshakeTimedOut,
    ConnectionToServerFailed,
    ServerHostnameCouldNotBeResolved,
)
from sslyze.plugins.certificate_info._certificate_utils import (
    parse_subject_alternative_name_extension,
    get_common_names,
)
from sslyze.plugins.openssl_cipher_suites._test_cipher_suite import _set_cipher_suite_string
from sslyze.plugins.openssl_cipher_suites.cipher_suites import CipherSuitesRepository
from sslyze.scanner.models import CipherSuitesScanAttempt
from sslyze.server_connectivity import ServerConnectivityInfo

from checks import scoring
from checks.caa.retrieval import retrieve_parse_caa
from checks.models import (
    DaneStatus,
    ZeroRttStatus,
    KexHashFuncStatus,
    CipherOrderStatus,
)
from checks.resolver import dns_resolve_tlsa, DNSSECStatus, dns_resolve_a
from checks.tasks.tls import TLSException
from checks.tasks.tls.evaluation import (
    TLSProtocolEvaluation,
    TLSForwardSecrecyParameterEvaluation,
    TLSCipherEvaluation,
    KeyExchangeHashFunctionEvaluation,
    TLSCipherOrderEvaluation,
    TLSOCSPEvaluation,
    TLSRenegotiationEvaluation,
    TLSExtendedMasterSecretEvaluation,
)
from checks.tasks.tls.tls_constants import (
    CERT_SIGALG_GOOD,
    CERT_CURVES_GOOD,
    CERT_EC_CURVES_GOOD,
    CERT_EC_CURVES_PHASE_OUT,
    MAIL_ALTERNATE_CONNLIMIT_HOST_SUBSTRS,
    CERT_RSA_MIN_GOOD_KEY_SIZE,
    CERT_RSA_MIN_PHASE_OUT_KEY_SIZE,
    SIGNATURE_ALGORITHMS_BAD_HASH,
    SIGNATURE_ALGORITHMS_PHASE_OUT_HASH,
)
from internetnl import log

SSLYZE_NETWORK_TIMEOUT = 10

SSLYZE_SCAN_COMMANDS = {
    ScanCommand.TLS_COMPRESSION,
    ScanCommand.TLS_1_3_EARLY_DATA,
    ScanCommand.SESSION_RENEGOTIATION,
    ScanCommand.ELLIPTIC_CURVES,
}
SSLYZE_SCAN_COMMANDS_FOR_TLS = {
    TlsVersionEnum.SSL_2_0: ScanCommand.SSL_2_0_CIPHER_SUITES,
    TlsVersionEnum.SSL_3_0: ScanCommand.SSL_3_0_CIPHER_SUITES,
    TlsVersionEnum.TLS_1_0: ScanCommand.TLS_1_0_CIPHER_SUITES,
    TlsVersionEnum.TLS_1_1: ScanCommand.TLS_1_1_CIPHER_SUITES,
    TlsVersionEnum.TLS_1_2: ScanCommand.TLS_1_2_CIPHER_SUITES,
    TlsVersionEnum.TLS_1_3: ScanCommand.TLS_1_3_CIPHER_SUITES,
}
# Some of the code in this file calls
# ServerConnectivityInfo.get_preconfigured_tls_connection
# before any other scans are done. This call requires a ServerTLSProbingResult,
# however, the values inside it are never used, as all our calls use an explicit
# TLS version setting. Therefore, this shared fake is used, of which the actual
# settings do not matter. Just a nassl API oddity.
FAKE_SERVER_TLS_PROBING_RESULT = ServerTlsProbingResult(
    highest_tls_version_supported=TlsVersionEnum.TLS_1_3,
    cipher_suite_supported="",
    client_auth_requirement=ClientAuthRequirementEnum.DISABLED,
    supports_ecdh_key_exchange=True,
)

with open(settings.CA_FINGERPRINTS) as f:
    root_fingerprints = f.read().splitlines()


class ChecksMode(Enum):
    WEB = (0,)
    MAIL = 1


def dane(
    url: str,
    port: int,
    chain: List[Certificate],
    score_none: scoring.Score,
    score_none_bogus: scoring.Score,
    score_failed: scoring.Score,
    score_validated: scoring.Score,
):
    """
    Check if there are TLSA records, if they are valid and if a DANE rollover
    scheme is currently in place.

    """
    score = score_none
    status = DaneStatus.none
    records = []
    stdout = ""
    rollover = False

    dane_qname = f"_{port}._tcp.{url}"
    dane_data = None
    dnssec_status = None
    try:
        rrset, dnssec_status = dns_resolve_tlsa(dane_qname)
        dane_data = [(rr.usage, rr.selector, rr.mtype, binascii.hexlify(rr.cert).decode("ascii")) for rr in rrset]
        if dnssec_status == DNSSECStatus.BOGUS:
            status = DaneStatus.none_bogus
            score = score_none_bogus
    except (NXDOMAIN, NoAnswer, NoNameservers, LifetimeTimeout, EmptyLabel):
        pass

    if not dane_data or dnssec_status != DNSSECStatus.SECURE:
        return dict(
            dane_score=score,
            dane_status=status,
            dane_log=stdout,
            dane_records=records,
            dane_rollover=rollover,
        )

    # Try to look up an A record for this qname, likely resulting in nxdomain, which must not be bogus
    try:
        dns_resolve_a(dane_qname)
    except (NoAnswer, NoNameservers, LifetimeTimeout, EmptyLabel):
        pass
    except NXDOMAIN as nxdomain:
        a_dnssec_status = DNSSECStatus.from_message(nxdomain.response(dane_qname))
        if a_dnssec_status == DNSSECStatus.BOGUS:
            return dict(
                dane_score=score_none_bogus,
                dane_status=DaneStatus.none_bogus,
                dane_log=stdout,
                dane_records=records,
                dane_rollover=rollover,
            )

    # Record TLSA data and also check for DANE rollover types.
    # Accepted pairs are:
    # * 3 x x - 3 x x
    # * 3 x x - 2 x x
    two_x_x = 0
    three_x_x = 0
    for cert_usage, selector, match, data in dane_data:
        if port == 25 and cert_usage in (0, 1):
            # Ignore PKIX TLSA records for mail.
            continue

        records.append(f"{cert_usage} {selector} {match} {data}")
        if cert_usage == 2:
            two_x_x += 1
        elif cert_usage == 3:
            three_x_x += 1

    if not records:
        return dict(
            dane_score=score,
            dane_status=status,
            dane_log=stdout,
            dane_records=records,
            dane_rollover=rollover,
        )

    if three_x_x > 1 or (three_x_x and two_x_x):
        rollover = True

    # Remove the trailing dot if any.
    hostname = url.rstrip(".")

    chain_pem = []
    for cert in chain:
        chain_pem.append(cert.public_bytes(Encoding.PEM).decode("ascii"))
    chain_txt = "\n".join(chain_pem)
    resolver = socket.gethostbyname(settings.RESOLVER_INTERNAL_VALIDATING)
    with subprocess.Popen(
        [
            settings.LDNS_DANE,
            "-c",
            "/dev/stdin",  # Read certificate chain from stdin
            "-n",  # Do not validate hostname
            "-T",  # Exit status 2 for PKIX without (secure) TLSA records
            "-r",
            resolver,
            "-f",
            settings.CA_CERTIFICATES,  # CA file
            "verify",
            hostname,
            str(port),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
        universal_newlines=True,
    ) as proc:
        try:
            res = proc.communicate(input=chain_txt, timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            res = proc.communicate()

    # status 0: DANE validate
    # status 1: ERROR
    # status 2: PKIX ok, no TLSA
    if res:
        stdout, stderr = res

        if "No usable TLSA records" in stdout or "No usable TLSA records" in stderr:
            score = score_failed
            status = DaneStatus.failed
        elif "No TLSA records" not in stdout and "No TLSA records" not in stderr:
            if proc.returncode == 0:
                score = score_validated
                status = DaneStatus.validated
            elif proc.returncode == 1:
                score = score_failed
                status = DaneStatus.failed

        # Log stderr if stdout is empty.
        if not stdout:
            stdout = stderr

    return dict(
        dane_score=score,
        dane_status=status,
        dane_log=stdout,
        dane_records=records,
        dane_rollover=rollover,
    )


def is_root_cert(cert: Certificate) -> bool:
    """
    Check if the certificate is a root certificate.
    """
    digest = cert.fingerprint(hashes.SHA1())
    digest = hexlify(digest).decode("ascii")
    return digest.upper() in root_fingerprints


def get_common_name(cert: Certificate) -> str:
    """
    Get the commonName of the certificate.
    """
    value = "-"
    try:
        common_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0]
        if common_name:
            value = common_name.value
    except (IndexError, ValueError):
        pass
    return value


def cert_checks(hostname: str, mode: ChecksMode, af_ip_pair=None, *args, **kwargs):
    """
    Perform certificate checks, such as trust, name match. Also scans the server.
    """
    log.info(f"starting cert sslyze scan for {hostname} {af_ip_pair} {mode}")
    # cryptography's PolicyBuilder.build_server_verifier is called through sslyze cert chain analyser
    # and does not allow the trailing dot we get from DNS records.
    # This only affects CERTIFICATE_INFO, and only if the hostname came from DNS.
    hostname_no_trailing_dot = hostname.rstrip(".")
    scan_commands_extra_arguments = ScanCommandsExtraArguments(
        certificate_info=CertificateInfoExtraArgument(custom_ca_file=Path(settings.CA_CERTIFICATES)),
    )
    if mode == ChecksMode.WEB:
        port = 443
        scan = ServerScanRequest(
            server_location=ServerNetworkLocation(
                hostname=hostname_no_trailing_dot, ip_address=af_ip_pair[1], port=port
            ),
            network_configuration=ServerNetworkConfiguration(
                tls_server_name_indication=hostname_no_trailing_dot,
                http_user_agent=settings.USER_AGENT,
                network_timeout=SSLYZE_NETWORK_TIMEOUT,
            ),
            scan_commands={ScanCommand.CERTIFICATE_INFO},
            scan_commands_extra_arguments=scan_commands_extra_arguments,
        )
    elif mode == ChecksMode.MAIL:
        port = 25
        scan = ServerScanRequest(
            server_location=ServerNetworkLocation(hostname=hostname_no_trailing_dot, port=port),
            network_configuration=ServerNetworkConfiguration(
                tls_server_name_indication=hostname_no_trailing_dot,
                tls_opportunistic_encryption=ProtocolWithOpportunisticTlsEnum.SMTP,
                smtp_ehlo_hostname=settings.SMTP_EHLO_DOMAIN,
                network_timeout=SSLYZE_NETWORK_TIMEOUT,
            ),
            scan_commands={ScanCommand.CERTIFICATE_INFO},
            scan_commands_extra_arguments=scan_commands_extra_arguments,
        )
    else:
        raise ValueError
    scanner = Scanner(per_server_concurrent_connections_limit=1)
    scanner.queue_scans([scan])
    result = next(scanner.get_results())
    if result.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
        log.info(f"sslyze scan for cert on {hostname} {af_ip_pair} {mode} failed: no connectivity")
        return dict(tls_cert=False)
    raise_sslyze_errors(result)

    if mode == ChecksMode.WEB:
        trusted_score_good = scoring.WEB_TLS_TRUSTED_GOOD
        trusted_score_bad = scoring.WEB_TLS_TRUSTED_BAD
        hostmatch_score_good = scoring.WEB_TLS_HOSTMATCH_GOOD
        hostmatch_score_bad = scoring.WEB_TLS_HOSTMATCH_BAD
    elif mode == ChecksMode.MAIL:
        trusted_score_good = scoring.MAIL_TLS_TRUSTED_GOOD
        trusted_score_bad = scoring.MAIL_TLS_TRUSTED_BAD
        hostmatch_score_good = scoring.MAIL_TLS_HOSTMATCH_GOOD
        hostmatch_score_bad = scoring.MAIL_TLS_HOSTMATCH_BAD
    else:
        raise ValueError(f"Unknown checks mode: {mode}")

    if (
        not result.scan_result.certificate_info.result
        or not result.scan_result.certificate_info.result.certificate_deployments
    ):
        return dict(tls_cert=False)

    cert_deployment = result.scan_result.certificate_info.result.certificate_deployments[0]
    leaf_cert = cert_deployment.received_certificate_chain[0]

    hostmatch_bad = []
    hostmatch_score = hostmatch_score_good
    if not _certificate_matches_hostname(leaf_cert, hostname_no_trailing_dot):
        hostmatch_score = hostmatch_score_bad

        # Extract all names from a certificate, taken from sslyze' _cert_chain_analyzer.py
        subj_alt_name_ext = parse_subject_alternative_name_extension(leaf_cert)
        certificate_names = set(
            get_common_names(leaf_cert.subject) + subj_alt_name_ext.dns_names + subj_alt_name_ext.ip_addresses
        )
        hostmatch_bad = certificate_names

    trusted_score = trusted_score_good if cert_deployment.verified_certificate_chain else trusted_score_bad
    pubkey_score, pubkey_bad, pubkey_phase_out = check_pubkey(cert_deployment.received_certificate_chain, mode)

    # NCSC 3.3.2 / 3.3.5
    sigalg_bad = {}
    sigalg_score = scoring.WEB_TLS_SIGNATURE_GOOD
    for cert in cert_deployment.received_certificate_chain:
        if not is_root_cert(cert):
            sigalg = cert.signature_algorithm_oid
            if sigalg not in CERT_SIGALG_GOOD:
                sigalg_bad[get_common_name(cert)] = sigalg._name
                sigalg_score = scoring.WEB_TLS_SIGNATURE_BAD

    chain_str = []
    for cert in cert_deployment.received_certificate_chain:
        chain_str.append(get_common_name(cert))

    dane_results = dane(
        hostname,
        port,
        cert_deployment.received_certificate_chain,
        scoring.WEB_TLS_DANE_NONE,
        scoring.WEB_TLS_DANE_NONE_BOGUS,
        scoring.WEB_TLS_DANE_FAILED,
        scoring.WEB_TLS_DANE_VALIDATED,
    )

    caa_result = retrieve_parse_caa(hostname)

    results = dict(
        tls_cert=True,
        chain=chain_str,
        # The trusted value is originally an errno from the validation call
        trusted=0
        if trusted_score == scoring.MAIL_TLS_TRUSTED_GOOD
        else 20,  # X509VerificationCodes.ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY,
        trusted_score=trusted_score,
        pubkey_bad=pubkey_bad,
        pubkey_phase_out=pubkey_phase_out,
        pubkey_score=pubkey_score,
        sigalg_bad=sigalg_bad,
        sigalg_score=sigalg_score,
        hostmatch_bad=hostmatch_bad,
        hostmatch_score=hostmatch_score,
        caa_result=caa_result,
    )
    results.update(dane_results)

    return results


def _certificate_matches_hostname(certificate: Certificate, server_hostname: str) -> bool:
    """Verify that the certificate was issued for the given hostname."""
    # Extract the names from the certificate to create the properly-formatted dictionary
    try:
        cert_subject = certificate.subject
    except ValueError:
        # Cryptography could not parse the certificate https://github.com/nabla-c0d3/sslyze/issues/495
        return False

    subj_alt_name_ext = parse_subject_alternative_name_extension(certificate)
    subj_alt_name_as_list = [("DNS", name) for name in subj_alt_name_ext.dns_names]
    subj_alt_name_as_list.extend([("IP Address", ip) for ip in subj_alt_name_ext.ip_addresses])

    certificate_names = {
        "subject": (tuple([("commonName", name) for name in get_common_names(cert_subject)]),),
        "subjectAltName": tuple(subj_alt_name_as_list),
    }
    # CertificateError is raised on failure
    try:
        match_hostname(certificate_names, server_hostname)  # type: ignore
        return True
    except CertificateError:
        return False


def check_pubkey(certificates: List[Certificate], mode: ChecksMode):
    """
    Check that all provided certificates meet NCSC requirements, except root.
    """
    # NCSC guidelines 3.3.2.x
    bad_pubkey = []
    phase_out_pubkey = []
    if mode == ChecksMode.WEB:
        pubkey_score_good = scoring.WEB_TLS_PUBKEY_GOOD
        pubkey_score_bad = scoring.WEB_TLS_PUBKEY_BAD
    elif mode == ChecksMode.MAIL:
        pubkey_score_good = scoring.MAIL_TLS_PUBKEY_GOOD
        pubkey_score_bad = scoring.MAIL_TLS_PUBKEY_BAD
    else:
        raise ValueError(f"Unknown checks mode: {mode}")
    pubkey_score = pubkey_score_good
    for cert in certificates:
        if is_root_cert(cert):
            continue

        common_name = get_common_name(cert)
        public_key = cert.public_key()
        key_type = type(public_key)
        curve = None
        if hasattr(public_key, "curve"):
            curve = public_key.curve.__class__

        is_good = (
            (isinstance(public_key, rsa.RSAPublicKey) and public_key.key_size >= CERT_RSA_MIN_GOOD_KEY_SIZE)
            or (key_type in CERT_CURVES_GOOD)
            or (isinstance(public_key, EllipticCurvePublicKey) and curve in CERT_EC_CURVES_GOOD)
        )

        if is_good:
            continue

        key_size = getattr(public_key, "key_size", None)
        message = f"{common_name}: {key_type.__name__}"
        if key_size is not None:
            message += f"-{key_size}"
        if curve:
            message += f", curve: {curve}"

        is_phase_out = (curve in CERT_EC_CURVES_PHASE_OUT) or (
            isinstance(public_key, rsa.RSAPublicKey) and public_key.key_size >= CERT_RSA_MIN_PHASE_OUT_KEY_SIZE
        )

        if is_phase_out:
            phase_out_pubkey.append(message)
        else:
            bad_pubkey.append(message)
            pubkey_score = pubkey_score_bad
    return pubkey_score, bad_pubkey, phase_out_pubkey


def check_mail_tls_multiple(server_tuples) -> Dict[str, Dict[str, Any]]:
    """
    Perform sslyze probing on all mail servers, in parallel.
    """
    scans = []
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_server = {}

        for server in server_tuples:
            future = executor.submit(_generate_mail_server_scan_request, server)
            future_to_server[future] = server

        for future in concurrent.futures.as_completed(future_to_server):
            server = future_to_server[future]
            scan_request, ems_evaluation = future.result()

            if scan_request:
                scans.append(scan_request)
            else:
                results[server] = dict(server_reachable=False, tls_enabled=False)

    if not scans:
        return results
    connection_limit = connection_limit_for_scans(scans)
    for all_suites, result, error in run_sslyze(scans, connection_limit=connection_limit):
        if error:
            log.info(f"sslyze scan for mail failed: {error}")
            results[result.server_location.hostname] = dict(server_reachable=False, tls_enabled=False)
            continue
        log.debug(f"sslyze mail scan complete for {result.server_location.hostname}, other scans may be pending")
        results[result.server_location.hostname] = check_mail_tls(result, all_suites, ems_evaluation)
        log.debug(f"check_mail_tls complete for {result.server_location.hostname}")
    return results


def connection_limit_for_scans(scans: List[ServerScanRequest]):
    """
    Determine the appropriate connection limit for a mail server.
    Sometimes we set this higher, due to anti-spam slowness.
    """
    hostnames = [scan.server_location.hostname for scan in scans]
    for hostname_substr, limit in MAIL_ALTERNATE_CONNLIMIT_HOST_SUBSTRS.items():
        if any([hostname_substr in hostname for hostname in hostnames]):
            log.info(f"conn limit raised to: {limit} for {hostname_substr} found in {hostnames}")
            return limit
    return 1


def _generate_mail_server_scan_request(
    mx_hostname: str,
) -> Tuple[Optional[ServerScanRequest], TLSExtendedMasterSecretEvaluation]:
    """
    Generate the scan request (sslyze scan commands) for a mail server.
    Includes resolving and determining supported TLS versions.
    """
    try:
        server_location = ServerNetworkLocation(hostname=mx_hostname, port=25)
    except ServerHostnameCouldNotBeResolved:
        log.info(f"unable to resolve MX host {mx_hostname}, marking server unreachable")
        return None, TLSExtendedMasterSecretEvaluation()
    network_configuration = ServerNetworkConfiguration(
        tls_server_name_indication=mx_hostname.rstrip("."),
        tls_opportunistic_encryption=ProtocolWithOpportunisticTlsEnum.SMTP,
        smtp_ehlo_hostname=settings.SMTP_EHLO_DOMAIN,
        network_timeout=SSLYZE_NETWORK_TIMEOUT,
    )
    supported_tls_versions, extended_master_secret_evaluation = check_supported_tls_versions(
        ServerConnectivityInfo(
            server_location=server_location,
            network_configuration=network_configuration,
            tls_probing_result=FAKE_SERVER_TLS_PROBING_RESULT,
        )
    )
    if not supported_tls_versions:
        log.info(f"no TLS version support found for MX host {mx_hostname}, marking server unreachable")
        return None, extended_master_secret_evaluation
    scan_commands = SSLYZE_SCAN_COMMANDS | {
        SSLYZE_SCAN_COMMANDS_FOR_TLS[tls_version] for tls_version in supported_tls_versions
    }

    return (
        ServerScanRequest(
            server_location=server_location,
            network_configuration=network_configuration,
            scan_commands=scan_commands,
            scan_commands_extra_arguments=ScanCommandsExtraArguments(
                session_renegotiation=SessionRenegotiationExtraArgument(
                    client_renegotiation_attempts=TLSRenegotiationEvaluation.SCAN_RENEGOTIATION_LIMIT
                ),
            ),
        ),
        extended_master_secret_evaluation,
    )


def check_mail_tls(
    result: ServerScanResult,
    all_suites: List[CipherSuitesScanAttempt],
    extended_master_secret_evaluation: TLSExtendedMasterSecretEvaluation,
):
    """
    Perform evaluation and additional probes for a single mail server.
    This happens after sslyze has already been run on it.
    """
    prots_accepted = [suites.result.tls_version_used for suites in all_suites if suites.result.is_tls_version_supported]
    ciphers_accepted = [cipher for suites in all_suites for cipher in suites.result.accepted_cipher_suites]
    prots_accepted.sort(key=lambda t: t.value, reverse=True)

    protocol_evaluation = TLSProtocolEvaluation.from_protocols_accepted(prots_accepted)
    fs_evaluation = TLSForwardSecrecyParameterEvaluation.from_ciphers_accepted(ciphers_accepted)
    cipher_evaluation = TLSCipherEvaluation.from_ciphers_accepted(ciphers_accepted)

    server_conn_info = ServerConnectivityInfo(
        server_location=result.server_location,
        network_configuration=result.network_configuration,
        tls_probing_result=result.connectivity_result,
    )
    cipher_order_evaluation = test_cipher_order(
        server_conn_info,
        prots_accepted,
        cipher_evaluation,
    )
    key_exchange_hash_evaluation = test_key_exchange_hash(server_conn_info)

    renegotiation_evaluation = TLSRenegotiationEvaluation.from_session_renegotiation_scan_result(
        result.scan_result.session_renegotiation.result
    )
    cert_results = cert_checks(result.server_location.hostname, ChecksMode.MAIL)

    # HACK for DANE-TA(2) and hostname mismatch!
    # Give a good hosmatch score if DANE-TA *is not* present.
    if cert_results["tls_cert"] and not has_daneTA(cert_results["dane_records"]) and cert_results["hostmatch_bad"]:
        cert_results["hostmatch_score"] = scoring.MAIL_TLS_HOSTMATCH_GOOD

    results = dict(
        tls_enabled=True,
        tls_enabled_score=scoring.MAIL_TLS_STARTTLS_EXISTS_GOOD,
        prots_bad=protocol_evaluation.bad_str,
        prots_phase_out=protocol_evaluation.phase_out_str,
        prots_good=protocol_evaluation.good_str,
        prots_sufficient=protocol_evaluation.sufficient_str,
        prots_score=protocol_evaluation.score,
        ciphers_bad=cipher_evaluation.ciphers_bad_str,
        ciphers_phase_out=cipher_evaluation.ciphers_phase_out_str,
        ciphers_score=cipher_evaluation.score,
        cipher_order_score=cipher_order_evaluation.score,
        cipher_order=cipher_order_evaluation.status,
        cipher_order_violation=cipher_order_evaluation.violation,
        secure_reneg=renegotiation_evaluation.status_secure_renegotiation,
        secure_reneg_score=renegotiation_evaluation.score_secure_renegotiation,
        client_reneg=renegotiation_evaluation.status_client_initiated_renegotiation,
        client_reneg_score=renegotiation_evaluation.score_client_initiated_renegotiation,
        compression=result.scan_result.tls_compression.result.supports_compression
        if result.scan_result.tls_compression.result
        else None,
        compression_score=(
            scoring.WEB_TLS_COMPRESSION_BAD
            if result.scan_result.tls_compression.result.supports_compression
            else scoring.WEB_TLS_COMPRESSION_GOOD
        ),
        dh_param=fs_evaluation.max_dh_size,
        ecdh_param=fs_evaluation.max_ec_size,
        fs_bad=list(fs_evaluation.bad_str),
        fs_phase_out=list(fs_evaluation.phase_out_str),
        fs_score=fs_evaluation.score,
        zero_rtt=(
            ZeroRttStatus.bad
            if result.scan_result.tls_1_3_early_data.result.supports_early_data
            else ZeroRttStatus.good
        ),
        zero_rtt_score=(
            scoring.WEB_TLS_ZERO_RTT_BAD
            if result.scan_result.tls_1_3_early_data.result.supports_early_data
            else scoring.WEB_TLS_ZERO_RTT_GOOD
        ),
        kex_hash_func=key_exchange_hash_evaluation.status,
        kex_hash_func_score=key_exchange_hash_evaluation.score,
        extended_master_secret=extended_master_secret_evaluation.status,
        extended_master_secret_score=extended_master_secret_evaluation.score,
    )
    results.update(cert_results)
    return results


def has_daneTA(tlsa_records):
    """
    Check if any of the TLSA records is of type DANE-TA(2).
    """
    for tlsa in tlsa_records:
        if tlsa.startswith("2"):
            return True
    return False


def check_web_tls(url, af_ip_pair=None, *args, **kwargs):
    """
    Check the webserver's TLS configuration.
    """
    server_location = ServerNetworkLocation(hostname=url, ip_address=af_ip_pair[1])
    network_configuration = ServerNetworkConfiguration(
        tls_server_name_indication=url.rstrip("."),
        http_user_agent=settings.USER_AGENT,
        network_timeout=SSLYZE_NETWORK_TIMEOUT,
    )
    supported_tls_versions, extended_master_secret_evaluation = check_supported_tls_versions(
        ServerConnectivityInfo(
            server_location=server_location,
            network_configuration=network_configuration,
            tls_probing_result=FAKE_SERVER_TLS_PROBING_RESULT,
        )
    )
    scan_commands = (
        SSLYZE_SCAN_COMMANDS
        | {SSLYZE_SCAN_COMMANDS_FOR_TLS[tls_version] for tls_version in supported_tls_versions}
        | {ScanCommand.CERTIFICATE_INFO}
    )
    log.info(f"==== precheck on {server_location} supports {supported_tls_versions} {scan_commands=}")
    scan = ServerScanRequest(
        server_location=server_location,
        network_configuration=network_configuration,
        scan_commands=scan_commands,
        scan_commands_extra_arguments=ScanCommandsExtraArguments(
            certificate_info=CertificateInfoExtraArgument(custom_ca_file=Path(settings.CA_CERTIFICATES)),
            session_renegotiation=SessionRenegotiationExtraArgument(
                client_renegotiation_attempts=TLSRenegotiationEvaluation.SCAN_RENEGOTIATION_LIMIT
            ),
        ),
    )
    all_suites, result, error = next(run_sslyze([scan], connection_limit=25))
    if error:
        log.info(f"sslyze scan for web on {url} failed: {error}")
        return dict(server_reachable=False, tls_enabled=False)

    ciphers_accepted = [cipher for suites in all_suites for cipher in suites.result.accepted_cipher_suites]
    protocol_evaluation = TLSProtocolEvaluation.from_protocols_accepted(supported_tls_versions)
    fs_evaluation = TLSForwardSecrecyParameterEvaluation.from_ciphers_accepted(ciphers_accepted)
    cipher_evaluation = TLSCipherEvaluation.from_ciphers_accepted(ciphers_accepted)

    server_conn_info = ServerConnectivityInfo(
        server_location=result.server_location,
        network_configuration=result.network_configuration,
        tls_probing_result=result.connectivity_result,
    )
    cipher_order_evaluation = test_cipher_order(
        server_conn_info,
        supported_tls_versions,
        cipher_evaluation,
    )
    key_exchange_hash_evaluation = test_key_exchange_hash(server_conn_info)
    renegotiation_evaluation = TLSRenegotiationEvaluation.from_session_renegotiation_scan_result(
        result.scan_result.session_renegotiation.result
    )

    ocsp_evaluation = TLSOCSPEvaluation.from_certificate_deployments(
        result.scan_result.certificate_info.result.certificate_deployments[0]
    )

    probe_result = dict(
        tls_enabled=True,
        prots_bad=protocol_evaluation.bad_str,
        prots_phase_out=protocol_evaluation.phase_out_str,
        prots_good=protocol_evaluation.good_str,
        prots_sufficient=protocol_evaluation.sufficient_str,
        prots_score=protocol_evaluation.score,
        ciphers_bad=cipher_evaluation.ciphers_bad_str,
        ciphers_phase_out=cipher_evaluation.ciphers_phase_out_str,
        ciphers_score=cipher_evaluation.score,
        cipher_order_score=cipher_order_evaluation.score,
        cipher_order=cipher_order_evaluation.status,
        cipher_order_violation=cipher_order_evaluation.violation,
        secure_reneg=renegotiation_evaluation.status_secure_renegotiation,
        secure_reneg_score=renegotiation_evaluation.score_secure_renegotiation,
        client_reneg=renegotiation_evaluation.status_client_initiated_renegotiation,
        client_reneg_score=renegotiation_evaluation.score_client_initiated_renegotiation,
        compression=result.scan_result.tls_compression.result.supports_compression
        if result.scan_result.tls_compression.result
        else None,
        compression_score=(
            scoring.WEB_TLS_COMPRESSION_BAD
            if result.scan_result.tls_compression.result.supports_compression
            else scoring.WEB_TLS_COMPRESSION_GOOD
        ),
        dh_param=fs_evaluation.max_dh_size,
        ecdh_param=fs_evaluation.max_ec_size,
        fs_bad=list(fs_evaluation.bad_str),
        fs_phase_out=list(fs_evaluation.phase_out_str),
        fs_score=fs_evaluation.score,
        zero_rtt=(
            ZeroRttStatus.bad
            if result.scan_result.tls_1_3_early_data.result.supports_early_data
            else ZeroRttStatus.good
        ),
        zero_rtt_score=(
            scoring.WEB_TLS_ZERO_RTT_BAD
            if result.scan_result.tls_1_3_early_data.result.supports_early_data
            else scoring.WEB_TLS_ZERO_RTT_GOOD
        ),
        ocsp_stapling=ocsp_evaluation.status,
        ocsp_stapling_score=ocsp_evaluation.score,
        kex_hash_func=key_exchange_hash_evaluation.status,
        kex_hash_func_score=key_exchange_hash_evaluation.score,
        extended_master_secret=extended_master_secret_evaluation.status,
        extended_master_secret_score=extended_master_secret_evaluation.score,
    )
    return probe_result


def run_sslyze(
    scans: List[ServerScanRequest], connection_limit: int
) -> Generator[Tuple[List[CipherSuitesScanAttempt], ServerScanResult, Optional[TLSException]], None, None]:
    """
    Run a set of sslyze scans in parallel.
    Starts each scan request at the same time, and yields them as soon as they are finished.
    This threading is handled inside sslyze.
    """
    log.debug(f"starting sslyze scan for {[scan.server_location for scan in scans]}")
    scanner = Scanner(
        per_server_concurrent_connections_limit=connection_limit,
    )
    scanner.queue_scans(scans)
    for result in scanner.get_results():
        log.debug(f"sslyze scan for {result.server_location} result: {result.scan_status}")
        if result.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
            yield [], result, TLSException(f"could not connect: {''.join(result.connectivity_error_trace.format())}")
            continue
        all_suites = [
            suite
            for suite in (
                result.scan_result.ssl_2_0_cipher_suites,
                result.scan_result.ssl_3_0_cipher_suites,
                result.scan_result.tls_1_0_cipher_suites,
                result.scan_result.tls_1_1_cipher_suites,
                result.scan_result.tls_1_2_cipher_suites,
                result.scan_result.tls_1_3_cipher_suites,
            )
            if suite and suite.result
        ]
        # Error is caught and returned here, as we may be running many scans.,
        # and don't want to abort all scans for one failure.
        try:
            raise_sslyze_errors(result)
        except TLSException as exc:
            yield all_suites, result, exc
            continue
        yield all_suites, result, None


def raise_sslyze_errors(result: ServerScanResult) -> None:
    """
    Determine whether the scan result contains any exceptions,
    and if it does, raise a TLSException for them.
    """
    last_error_trace = None
    for scan_result in vars(result.scan_result).values():
        error_trace = getattr(scan_result, "error_trace")
        if error_trace:
            last_error_trace = error_trace
            log.info(f"TLS scan on {result.server_location} failed: {error_trace}: {''.join(error_trace.format())}")
    if last_error_trace:
        raise TLSException(str(last_error_trace))


def test_key_exchange_hash(
    server_connectivity_info: ServerConnectivityInfo,
) -> KeyExchangeHashFunctionEvaluation:
    """
    Test key exchange hashes per NCSC 3.3.5.
    Note that this is not the certificate hash, or TLS cipher hash.
    There are few or no hosts that do not meet this requirement.
    """
    bad_hash_result = _test_connection_with_limited_sigalgs(server_connectivity_info, SIGNATURE_ALGORITHMS_BAD_HASH)
    if bad_hash_result:
        log.info(f"SHA2 key exchange check: negotiated bad sigalg ({bad_hash_result})")
        return KeyExchangeHashFunctionEvaluation(
            status=KexHashFuncStatus.bad,
            score=scoring.WEB_TLS_KEX_HASH_FUNC_BAD,
        )

    phase_out_hash_result = _test_connection_with_limited_sigalgs(
        server_connectivity_info, SIGNATURE_ALGORITHMS_PHASE_OUT_HASH
    )
    if phase_out_hash_result:
        log.info(f"SHA2 key exchange check: negotiated phase_out hash ({phase_out_hash_result})")
        return KeyExchangeHashFunctionEvaluation(
            status=KexHashFuncStatus.phase_out,
            score=scoring.WEB_TLS_KEX_HASH_FUNC_OK,
        )

    return KeyExchangeHashFunctionEvaluation(
        status=KexHashFuncStatus.good,
        score=scoring.WEB_TLS_KEX_HASH_FUNC_GOOD,
    )


def _test_connection_with_limited_sigalgs(
    server_connectivity_info: ServerConnectivityInfo, sigalgs: list[tuple[OpenSslDigestNidEnum, OpenSslEvpPkeyEnum]]
) -> Optional[OpenSslDigestNidEnum]:
    """
    Test whether the server accepts a connection with limited sigalgs through the signature_algorithms extension.
    Returns a (NID, EVP PKEY) if a match was found, None otherwise.
    """
    # This is only interesting on TLS 1.2 or older
    override_tls_version = None
    if server_connectivity_info.tls_probing_result.highest_tls_version_supported == TlsVersionEnum.TLS_1_3:
        override_tls_version = TlsVersionEnum.TLS_1_2
    ssl_connection = server_connectivity_info.get_preconfigured_tls_connection(
        override_tls_version=override_tls_version, should_use_legacy_openssl=False
    )
    ssl_connection.ssl_client.set_signature_algorithms(sigalgs)

    try:
        ssl_connection.connect()
        sigalg_nid = ssl_connection.ssl_client.get_peer_signature_nid()
        # Extra check as some servers will ignore the client and force a secure hash anyways.
        # OpenSSL will accept this, as it does know about the secure hash.
        # Note that while we can double-check this for the digest hash, we cannot check it for EVP PKEY.
        if sigalg_nid in [sa[0] for sa in sigalgs]:
            return sigalg_nid
    except (ClientCertificateRequested, ServerRejectedTlsHandshake, TlsHandshakeTimedOut, OpenSSLError):
        pass
    finally:
        ssl_connection.close()

    return None


def test_cipher_order(
    server_connectivity_info: ServerConnectivityInfo,
    tls_versions: List[TlsVersionEnum],
    cipher_evaluation: TLSCipherEvaluation,
) -> TLSCipherOrderEvaluation:
    """
    Determine whether there was a cipher order violation.
    We require supported ciphers to be ordered good>sufficient>phase out>bad.
    Within each level, the order is not significant to us.

    This test forms cipher strings of e.g. all supported sufficient followed
    by each good, and then expects the server to choose the good cipher.
    That assures us that the server prefers each good cipher over any lower cipher.
    This is tested at all levels that the server supported.
    """
    cipher_order_violation = []
    status = CipherOrderStatus.good
    if (
        not cipher_evaluation.ciphers_bad
        and not cipher_evaluation.ciphers_phase_out
        and not cipher_evaluation.ciphers_sufficient
    ) or tls_versions == [TlsVersionEnum.TLS_1_3]:
        return TLSCipherOrderEvaluation(
            violation=[],
            status=CipherOrderStatus.na,
            score=scoring.WEB_TLS_CIPHER_ORDER_GOOD,
        )

    tls_version = sorted([t for t in tls_versions if t != TlsVersionEnum.TLS_1_3], key=lambda t: t.value)[-1]

    order_tuples = [
        (
            CipherOrderStatus.sufficient_above_good,
            cipher_evaluation.ciphers_bad + cipher_evaluation.ciphers_phase_out + cipher_evaluation.ciphers_sufficient,
            # Make sure we do not mix in TLS 1.3 ciphers, all TLS 1.3 ciphers are good.
            cipher_evaluation.ciphers_good_no_tls13,
        ),
        (
            CipherOrderStatus.bad,
            cipher_evaluation.ciphers_bad + cipher_evaluation.ciphers_phase_out,
            cipher_evaluation.ciphers_sufficient,
        ),
        (CipherOrderStatus.bad, cipher_evaluation.ciphers_bad, cipher_evaluation.ciphers_phase_out),
    ]
    for fail_status, expected_less_preferred, expected_more_preferred_list in order_tuples:
        if cipher_order_violation:
            break
        # Sort CHACHA as later in the list, in case SSL_OP_PRIORITIZE_CHACHA is enabled #461
        expected_less_preferred.sort(key=lambda c: "CHACHA" in c.name)
        for expected_more_preferred in expected_more_preferred_list:
            if not expected_less_preferred or not expected_more_preferred:
                continue
            preferred_suite = find_most_preferred_cipher_suite(
                server_connectivity_info, tls_version, expected_less_preferred + [expected_more_preferred]
            )
            if preferred_suite != expected_more_preferred:
                cipher_order_violation = [preferred_suite.name, expected_more_preferred.name]
                status = fail_status
                log.info(
                    f"found cipher order violation for {server_connectivity_info.server_location.hostname}:"
                    f" preferred {preferred_suite.name} instead of {expected_more_preferred.name}, status {fail_status}"
                )
                break

    return TLSCipherOrderEvaluation(
        violation=cipher_order_violation,
        status=status,
        score=scoring.WEB_TLS_CIPHER_ORDER_BAD
        if status == CipherOrderStatus.bad
        else scoring.WEB_TLS_CIPHER_ORDER_GOOD,
    )


# adapted from sslyze.plugins.openssl_cipher_suites._test_cipher_suite.connect_with_cipher_suite
def find_most_preferred_cipher_suite(
    server_connectivity_info: ServerConnectivityInfo, tls_version: TlsVersionEnum, cipher_suites: List[CipherSuite]
) -> CipherSuite:
    suite_names = [suite.openssl_name for suite in cipher_suites]

    # OpenSSL is fine with invalid cipher names, as long as there are some ciphers selected it does support.
    # However, this may also happen in rare cases where parts of the suite are only supported in one OpenSSL
    # version, and another part in another. This appears very rare, so we log it and continue.
    # In theory, this can cause a small set of obscure cipher order violations to be undetected.
    unavailable_suites = [c for c in cipher_suites if not _check_cipher_suite_available(tls_version, c)]
    if unavailable_suites:
        log.warning(
            f"unable to include cipher suites {unavailable_suites} in cipher order testing for {tls_version.name} on"
            f" {server_connectivity_info.server_location.hostname} due to mix of required OpenSSL versions"
        )

    ssl_connection = server_connectivity_info.get_preconfigured_tls_connection(
        override_tls_version=tls_version, should_use_legacy_openssl=False
    )
    _set_cipher_suite_string(tls_version, ":".join(suite_names), ssl_connection.ssl_client)

    try:
        ssl_connection.connect()
    except ClientCertificateRequested:
        pass
    except (ServerRejectedTlsHandshake, TlsHandshakeTimedOut) as exc:
        raise TLSException(
            f"Unable to connect with (previously accepted) cipher suites {suite_names} to determine cipher order: {exc}"
        )
    finally:
        ssl_connection.close()

    selected_cipher = CipherSuitesRepository.get_cipher_suite_with_openssl_name(
        tls_version, ssl_connection.ssl_client.get_current_cipher_name()
    )
    return selected_cipher


def _check_cipher_suite_available(tls_version: TlsVersionEnum, cipher_suite: CipherSuite) -> bool:
    try:
        CipherSuitesRepository.get_cipher_suite_with_openssl_name(tls_version, cipher_suite.openssl_name)
        return True
    except ValueError:
        return False


def check_supported_tls_versions(
    server_connectivity_info: ServerConnectivityInfo,
) -> Tuple[List[TlsVersionEnum], TLSExtendedMasterSecretEvaluation]:
    """
    Determine which TLS versions are supported, and EMS support.
    Providing this info to sslyze improves on the bluntness of the scans.
    EMS is combined for efficiency, we just need access to any TLS 1.2 connection to check it.
    """
    supported_tls_versions = []
    ems_evaluation = TLSExtendedMasterSecretEvaluation()
    for tls_version in TlsVersionEnum:
        requires_legacy_openssl = tls_version not in [TlsVersionEnum.TLS_1_2, TlsVersionEnum.TLS_1_3]

        ssl_connection = server_connectivity_info.get_preconfigured_tls_connection(
            override_tls_version=tls_version, should_use_legacy_openssl=requires_legacy_openssl
        )
        try:
            ssl_connection.connect()
            supported_tls_versions.append(tls_version)
            ems_evaluation.update_for_connection(ssl_connection, tls_version)
        except (ConnectionToServerFailed, OpenSSLError, TlsHandshakeTimedOut) as exc:
            log.debug(
                f"Server {server_connectivity_info.server_location.hostname}"
                f"/{server_connectivity_info.server_location.ip_address}"
                f" rejected {tls_version.name}:"
                f" {str(exc).strip()} ({requires_legacy_openssl=})"
            )
        finally:
            ssl_connection.close()

    log.debug(
        f"Server {server_connectivity_info.server_location.hostname} TLS version precheck found "
        f"support for {supported_tls_versions}"
    )
    supported_tls_versions.sort(key=lambda t: t.value, reverse=True)
    return supported_tls_versions, ems_evaluation
