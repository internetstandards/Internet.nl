from binascii import hexlify
from enum import Enum
from pathlib import Path
from ssl import match_hostname, CertificateError
from typing import List, Tuple

import subprocess
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives._serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import rsa, dsa
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.x509 import Certificate
from django.conf import settings
from nassl.ssl_client import ClientCertificateRequested
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
)
from sslyze.errors import ServerRejectedTlsHandshake, TlsHandshakeTimedOut
from sslyze.plugins.certificate_info._certificate_utils import (
    parse_subject_alternative_name_extension,
    get_common_names,
)
from sslyze.plugins.openssl_cipher_suites._test_cipher_suite import _set_cipher_suite_string
from sslyze.plugins.openssl_cipher_suites._tls12_workaround import WorkaroundForTls12ForCipherSuites
from sslyze.plugins.openssl_cipher_suites.cipher_suites import CipherSuitesRepository
from sslyze.scanner.models import CipherSuitesScanAttempt
from sslyze.server_connectivity import ServerConnectivityInfo

from checks import scoring
from checks.models import (
    DaneStatus,
    ZeroRttStatus,
    KexHashFuncStatus,
    OcspStatus,
    CipherOrderStatus,
)
from checks.tasks.shared import resolve_dane
from checks.tasks.tls import TLSException
from checks.tasks.tls.evaluation import (
    TLSProtocolEvaluation,
    TLSForwardSecrecyParameterEvaluation,
    TLSCipherEvaluation,
    KeyExchangeHashFunctionEvaluation,
    TLSCipherOrderEvaluation,
)
from checks.tasks.tls.tls_constants import (
    CERT_SIGALG_GOOD,
    CERT_RSA_DSA_MIN_KEY_SIZE,
    CERT_CURVES_GOOD,
    CERT_CURVE_MIN_KEY_SIZE,
    CERT_EC_CURVES_GOOD,
    CERT_EC_CURVES_PHASE_OUT,
    SIGNATURE_ALGORITHMS_SHA2,
)
from internetnl import log

SSLYZE_SCAN_COMMANDS = {
    ScanCommand.SSL_2_0_CIPHER_SUITES,
    ScanCommand.SSL_3_0_CIPHER_SUITES,
    ScanCommand.TLS_1_0_CIPHER_SUITES,
    ScanCommand.TLS_1_1_CIPHER_SUITES,
    ScanCommand.TLS_1_2_CIPHER_SUITES,
    ScanCommand.TLS_1_3_CIPHER_SUITES,
    ScanCommand.TLS_COMPRESSION,
    ScanCommand.TLS_1_3_EARLY_DATA,
    ScanCommand.SESSION_RENEGOTIATION,
    ScanCommand.ELLIPTIC_CURVES,
}

with open(settings.CA_FINGERPRINTS) as f:
    root_fingerprints = f.read().splitlines()


class ChecksMode(Enum):
    WEB = (0,)
    MAIL = 1


def dane(
    url: str,
    port: int,
    chain: List[Certificate],
    task,
    dane_cb_data,
    score_none,
    score_none_bogus,
    score_failed,
    score_validated,
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

    continue_testing = False

    cb_data = dane_cb_data or resolve_dane(task, port, url)

    # Check if there is a TLSA record, if TLSA records are bogus or NXDOMAIN is
    # returned for the TLSA domain (faulty signer).
    if cb_data.get("bogus"):
        status = DaneStatus.none_bogus
        score = score_none_bogus
    elif cb_data.get("data") and cb_data.get("secure"):
        # If there is a secure TLSA record check for the existence of
        # possible bogus (unsigned) NXDOMAIN in A.
        tmp_data = resolve_dane(task, port, url, check_nxdomain=True)
        if tmp_data.get("nxdomain") and tmp_data.get("bogus"):
            status = DaneStatus.none_bogus
            score = score_none_bogus
        else:
            continue_testing = True

    if not continue_testing:
        return dict(
            dane_score=score,
            dane_status=status,
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
    for cert_usage, selector, match, data in cb_data["data"]:
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
    with subprocess.Popen(
        [
            settings.LDNS_DANE,
            "-c",
            "/dev/stdin",  # Read certificate chain from stdin
            "-n",  # Do not validate hostname
            "-T",  # Exit status 2 for PKIX without (secure) TLSA records
            "-r",
            settings.IPV4_IP_RESOLVER_INTERNAL_VALIDATING,  # Use internal unbound resolver
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


def is_root_cert(cert):
    """
    Check if the certificate is a root certificate.

    """
    digest = cert.fingerprint(hashes.SHA1())
    digest = hexlify(digest).decode("ascii")
    return digest.upper() in root_fingerprints


def get_common_name(cert):
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


def cert_checks(hostname, mode, task, af_ip_pair=None, dane_cb_data=None, *args, **kwargs):
    """
    Perform certificate checks.

    """
    log.info(f"starting cert sslyze scan for {hostname} {af_ip_pair} {mode}")
    # cryptography's PolicyBuilder.build_server_verifier is called through sslyze cert chain analyser
    # and does not allow the trailing dot we get from DNS records.
    # This only affects CERTIFICATE_INFO, and only if the hostname came from DNS.
    hostname_no_trailing_dot = hostname.rstrip(".")
    if mode == ChecksMode.WEB:
        port = 443
        scan = ServerScanRequest(
            server_location=ServerNetworkLocation(
                hostname=hostname_no_trailing_dot, ip_address=af_ip_pair[1], port=port
            ),
            network_configuration=ServerNetworkConfiguration(
                tls_server_name_indication=hostname_no_trailing_dot, http_user_agent=settings.USER_AGENT
            ),
            scan_commands={ScanCommand.CERTIFICATE_INFO},
            scan_commands_extra_arguments=ScanCommandsExtraArguments(
                certificate_info=CertificateInfoExtraArgument(custom_ca_file=Path(settings.CA_CERTIFICATES))
            ),
        )
    elif mode == ChecksMode.MAIL:
        port = 25
        scan = ServerScanRequest(
            server_location=ServerNetworkLocation(hostname=hostname_no_trailing_dot, port=port),
            network_configuration=ServerNetworkConfiguration(
                tls_server_name_indication=hostname_no_trailing_dot,
                tls_opportunistic_encryption=ProtocolWithOpportunisticTlsEnum.SMTP,
                smtp_ehlo_hostname=settings.SMTP_EHLO_DOMAIN,
            ),
            scan_commands={ScanCommand.CERTIFICATE_INFO},
            scan_commands_extra_arguments=ScanCommandsExtraArguments(
                certificate_info=CertificateInfoExtraArgument(custom_ca_file=Path(settings.CA_CERTIFICATES))
            ),
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

    # NCSC guideline B3-2
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
        task,
        dane_cb_data,
        scoring.WEB_TLS_DANE_NONE,
        scoring.WEB_TLS_DANE_NONE_BOGUS,
        scoring.WEB_TLS_DANE_FAILED,
        scoring.WEB_TLS_DANE_VALIDATED,
    )

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
    # NCSC guidelines B3-3, B5-1
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
        common_name = get_common_name(cert)
        public_key = cert.public_key()
        public_key_type = type(public_key)
        key_size = public_key.key_size

        failed_key_type = ""
        curve = ""
        # Note that DH fields are checked in the key exchange already
        # https://github.com/internetstandards/Internet.nl/pull/1218#issuecomment-1944496933
        if public_key_type is rsa.RSAPublicKey and key_size < CERT_RSA_DSA_MIN_KEY_SIZE:
            failed_key_type = public_key_type.__name__
        elif public_key_type is dsa.DSAPublicKey and key_size < CERT_RSA_DSA_MIN_KEY_SIZE:
            failed_key_type = public_key_type.__name__
        elif public_key_type in CERT_CURVES_GOOD and key_size < CERT_CURVE_MIN_KEY_SIZE:
            failed_key_type = public_key_type.__name__
        elif public_key_type is EllipticCurvePublicKey and public_key.curve not in CERT_EC_CURVES_GOOD:
            failed_key_type = public_key_type.__name__
        if failed_key_type:
            message = f"{common_name}: {failed_key_type}-{key_size} key_size"
            if curve:
                message += f", curve: {curve}"
            if public_key.curve in CERT_EC_CURVES_PHASE_OUT:
                phase_out_pubkey.append(message)
            else:
                bad_pubkey.append(message)
                pubkey_score = pubkey_score_bad
    return pubkey_score, bad_pubkey, phase_out_pubkey


def check_mail_tls(server, dane_cb_data, task):
    """
    Perform all the TLS related checks for this mail server in series.
    """
    scan = ServerScanRequest(
        server_location=ServerNetworkLocation(hostname=server, port=25),
        network_configuration=ServerNetworkConfiguration(
            tls_server_name_indication=server,
            tls_opportunistic_encryption=ProtocolWithOpportunisticTlsEnum.SMTP,
            smtp_ehlo_hostname=settings.SMTP_EHLO_DOMAIN,
        ),
        scan_commands=SSLYZE_SCAN_COMMANDS,
    )
    try:
        all_suites, result = run_sslyze(scan, connection_limit=1)
    except TLSException as exc:
        log.info(f"sslyze scan for mail on {server} failed: {exc}")
        return dict(server_reachable=False, tls_enabled=False)

    prots_accepted = [suites.result.tls_version_used for suites in all_suites if suites.result.is_tls_version_supported]
    ciphers_accepted = [cipher for suites in all_suites for cipher in suites.result.accepted_cipher_suites]
    prots_accepted.sort(key=lambda t: t.value, reverse=True)

    protocol_evaluation = TLSProtocolEvaluation.from_protocols_accepted(prots_accepted)
    fs_evaluation = TLSForwardSecrecyParameterEvaluation.from_ciphers_accepted(ciphers_accepted)
    cipher_evaluation = TLSCipherEvaluation.from_ciphers_accepted(ciphers_accepted)
    cipher_order_evaluation = test_cipher_order(
        ServerConnectivityInfo(
            server_location=result.server_location,
            network_configuration=result.network_configuration,
            tls_probing_result=result.connectivity_result,
        ),
        prots_accepted,
        cipher_evaluation,
    )
    cert_results = cert_checks(server, ChecksMode.MAIL, task, dane_cb_data)

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
        secure_reneg=result.scan_result.session_renegotiation.result.supports_secure_renegotiation,
        secure_reneg_score=(
            scoring.WEB_TLS_SECURE_RENEG_GOOD
            if result.scan_result.session_renegotiation.result.supports_secure_renegotiation
            else scoring.WEB_TLS_SECURE_RENEG_BAD
        ),
        client_reneg=result.scan_result.session_renegotiation.result.is_vulnerable_to_client_renegotiation_dos,
        client_reneg_score=(
            scoring.WEB_TLS_CLIENT_RENEG_BAD
            if result.scan_result.session_renegotiation.result.is_vulnerable_to_client_renegotiation_dos
            else scoring.WEB_TLS_CLIENT_RENEG_GOOD
        ),
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
        kex_hash_func=KexHashFuncStatus.good,
        kex_hash_func_score=scoring.WEB_TLS_KEX_HASH_FUNC_OK,
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
    scan = ServerScanRequest(
        server_location=ServerNetworkLocation(hostname=url, ip_address=af_ip_pair[1]),
        network_configuration=ServerNetworkConfiguration(
            tls_server_name_indication=url, http_user_agent=settings.USER_AGENT
        ),
        scan_commands=SSLYZE_SCAN_COMMANDS | {ScanCommand.CERTIFICATE_INFO},
        scan_commands_extra_arguments=ScanCommandsExtraArguments(
            certificate_info=CertificateInfoExtraArgument(custom_ca_file=Path(settings.CA_CERTIFICATES))
        ),
    )
    try:
        all_suites, result = run_sslyze(scan, connection_limit=25)
    except TLSException as exc:
        log.info(f"sslyze scan for web on {url} failed: {exc}")
        return dict(server_reachable=False, tls_enabled=False)

    prots_accepted = [suites.result.tls_version_used for suites in all_suites if suites.result.is_tls_version_supported]
    ciphers_accepted = [cipher for suites in all_suites for cipher in suites.result.accepted_cipher_suites]
    prots_accepted.sort(key=lambda t: t.value, reverse=True)

    protocol_evaluation = TLSProtocolEvaluation.from_protocols_accepted(prots_accepted)
    fs_evaluation = TLSForwardSecrecyParameterEvaluation.from_ciphers_accepted(ciphers_accepted)
    cipher_evaluation = TLSCipherEvaluation.from_ciphers_accepted(ciphers_accepted)
    cipher_order_evaluation = test_cipher_order(
        ServerConnectivityInfo(
            server_location=result.server_location,
            network_configuration=result.network_configuration,
            tls_probing_result=result.connectivity_result,
        ),
        prots_accepted,
        cipher_evaluation,
    )
    key_exchange_hash_evaluation = test_key_exchange_hash(
        ServerConnectivityInfo(
            server_location=result.server_location,
            network_configuration=result.network_configuration,
            tls_probing_result=result.connectivity_result,
        ),
    )

    ocsp_status = OcspStatus.ok
    if any(
        [d.ocsp_response_is_trusted is True for d in result.scan_result.certificate_info.result.certificate_deployments]
    ):
        ocsp_status = OcspStatus.good
    elif any(
        [
            d.ocsp_response_is_trusted is False
            for d in result.scan_result.certificate_info.result.certificate_deployments
        ]
    ):
        ocsp_status = OcspStatus.not_trusted

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
        secure_reneg=result.scan_result.session_renegotiation.result.supports_secure_renegotiation,
        secure_reneg_score=(
            scoring.WEB_TLS_SECURE_RENEG_GOOD
            if result.scan_result.session_renegotiation.result.supports_secure_renegotiation
            else scoring.WEB_TLS_SECURE_RENEG_BAD
        ),
        client_reneg=result.scan_result.session_renegotiation.result.is_vulnerable_to_client_renegotiation_dos,
        client_reneg_score=(
            scoring.WEB_TLS_CLIENT_RENEG_BAD
            if result.scan_result.session_renegotiation.result.is_vulnerable_to_client_renegotiation_dos
            else scoring.WEB_TLS_CLIENT_RENEG_GOOD
        ),
        compression=result.scan_result.tls_compression.result.supports_compression,
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
        ocsp_stapling=ocsp_status,
        ocsp_stapling_score=(
            scoring.WEB_TLS_OCSP_STAPLING_GOOD if ocsp_status == OcspStatus.good else scoring.WEB_TLS_OCSP_STAPLING_BAD
        ),
        kex_hash_func=key_exchange_hash_evaluation.status,
        kex_hash_func_score=key_exchange_hash_evaluation.score,
    )
    return probe_result


def run_sslyze(scan, connection_limit) -> Tuple[List[CipherSuitesScanAttempt], ServerScanResult]:
    log.debug(f"starting sslyze scan for {scan.server_location}")
    scanner = Scanner(
        per_server_concurrent_connections_limit=connection_limit, concurrent_server_scans_limit=connection_limit
    )
    scanner.queue_scans([scan])
    result = next(scanner.get_results())
    log.info(f"sslyze scan for {result.server_location} status result {result.scan_status}")
    if result.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
        raise TLSException(f"could not connect: {''.join(result.connectivity_error_trace.format())}")
    all_suites = [
        result.scan_result.ssl_2_0_cipher_suites,
        result.scan_result.ssl_3_0_cipher_suites,
        result.scan_result.tls_1_0_cipher_suites,
        result.scan_result.tls_1_1_cipher_suites,
        result.scan_result.tls_1_2_cipher_suites,
        result.scan_result.tls_1_3_cipher_suites,
    ]
    raise_sslyze_errors(result)
    return all_suites, result


def raise_sslyze_errors(result: ServerScanResult) -> None:
    last_error_trace = None
    for scan_result in vars(result.scan_result).values():
        error_trace = getattr(scan_result, "error_trace")
        if error_trace:
            last_error_trace = error_trace
            log.error(f"TLS scan on {result.server_location} failed: {error_trace}: {''.join(error_trace.format())}")
    if last_error_trace:
        raise TLSException(str(last_error_trace))


def test_key_exchange_hash(
    server_connectivity_info: ServerConnectivityInfo,
) -> KeyExchangeHashFunctionEvaluation:
    ssl_connection = server_connectivity_info.get_preconfigured_tls_connection(should_use_legacy_openssl=False)
    ssl_connection.ssl_client.set_sigalgs(SIGNATURE_ALGORITHMS_SHA2)

    try:
        ssl_connection.connect()
    except ClientCertificateRequested:
        pass
    except (ServerRejectedTlsHandshake, TlsHandshakeTimedOut) as exc:
        log.info(f"Failed SHA2 key exchange check: {exc}")
        return KeyExchangeHashFunctionEvaluation(
            status=KexHashFuncStatus.bad,
            score=scoring.WEB_TLS_KEX_HASH_FUNC_BAD,
        )
    finally:
        ssl_connection.close()

    return KeyExchangeHashFunctionEvaluation(
        status=KexHashFuncStatus.good,
        score=scoring.WEB_TLS_KEX_HASH_FUNC_GOOD,
    )


def test_cipher_order(
    server_connectivity_info: ServerConnectivityInfo,
    tls_versions: List[TlsVersionEnum],
    cipher_evaluation: TLSCipherEvaluation,
) -> TLSCipherOrderEvaluation:
    cipher_order_violation = []
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
            cipher_evaluation.ciphers_bad + cipher_evaluation.ciphers_phase_out + cipher_evaluation.ciphers_sufficient,
            cipher_evaluation.ciphers_good,
        ),
        (cipher_evaluation.ciphers_bad + cipher_evaluation.ciphers_phase_out, cipher_evaluation.ciphers_sufficient),
        (cipher_evaluation.ciphers_bad, cipher_evaluation.ciphers_phase_out),
    ]
    for expected_less_preferred, expected_more_preferred_list in order_tuples:
        if cipher_order_violation:
            break
        # Sort CHACHA as later in the list, in case SSL_OP_PRIORITIZE_CHACHA is enabled #461
        expected_less_preferred.sort(key=lambda c: "CHACHA" in c.name)
        print(f"checking server pref against: {[s.name for s in expected_more_preferred_list]}")
        for expected_more_preferred in expected_more_preferred_list:
            print(
                f"evaluating less {[s.name for s in expected_less_preferred]} vs "
                f"more {expected_more_preferred.name} TLS {tls_version}"
            )
            if not expected_less_preferred or not expected_more_preferred:
                continue
            preferred_suite = find_most_preferred_cipher_suite(
                server_connectivity_info, tls_version, expected_less_preferred + [expected_more_preferred]
            )
            if preferred_suite != expected_more_preferred:
                cipher_order_violation = [preferred_suite.name, expected_more_preferred.name]
                print(f"break out, got bad order: {cipher_order_violation}")
                break

    return TLSCipherOrderEvaluation(
        violation=cipher_order_violation,
        status=CipherOrderStatus.bad if cipher_order_violation else CipherOrderStatus.good,
        score=scoring.WEB_TLS_CIPHER_ORDER_BAD if cipher_order_violation else scoring.WEB_TLS_CIPHER_ORDER_GOOD,
    )


# adapted from sslyze.plugins.openssl_cipher_suites._test_cipher_suite.connect_with_cipher_suite
def find_most_preferred_cipher_suite(
    server_connectivity_info: ServerConnectivityInfo, tls_version: TlsVersionEnum, cipher_suites: List[CipherSuite]
) -> CipherSuite:
    suite_names = [suite.openssl_name for suite in cipher_suites]
    requires_legacy_openssl = True
    if tls_version == TlsVersionEnum.TLS_1_2:
        # For TLS 1.2, we need to pick the right version of OpenSSL depending on which cipher suite
        requires_legacy_openssl = any(
            [WorkaroundForTls12ForCipherSuites.requires_legacy_openssl(name) for name in suite_names]
        )
    elif tls_version == TlsVersionEnum.TLS_1_3:
        requires_legacy_openssl = False

    ssl_connection = server_connectivity_info.get_preconfigured_tls_connection(
        override_tls_version=tls_version, should_use_legacy_openssl=requires_legacy_openssl
    )
    print(f"{suite_names=}")
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
    print(f"from CS {[s.name for s in cipher_suites]} selected {selected_cipher}")
    return selected_cipher