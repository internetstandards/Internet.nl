from dataclasses import dataclass
from typing import List, Optional, Any, Set, cast

from cryptography.hazmat._oid import AuthorityInformationAccessOID, ExtensionOID
from cryptography.x509 import AuthorityInformationAccess, ExtensionNotFound
from nassl.ephemeral_key_info import EcDhEphemeralKeyInfo, DhEphemeralKeyInfo, OpenSslEvpPkeyEnum
from sslyze import (
    TlsVersionEnum,
    CipherSuiteAcceptedByServer,
    CipherSuite,
    CertificateDeploymentAnalysisResult,
    SessionRenegotiationScanResult,
)
from sslyze.plugins.openssl_cipher_suites.cipher_suites import _TLS_1_3_CIPHER_SUITES

from checks import scoring
from checks.models import (
    KexHashFuncStatus,
    CipherOrderStatus,
    OcspStatus,
    KexRSAPKCSStatus,
    TLSClientInitiatedRenegotiationStatus,
)
from checks.tasks.tls.tls_constants import (
    PROTOCOLS_GOOD,
    PROTOCOLS_SUFFICIENT,
    PROTOCOLS_PHASE_OUT,
    FS_EC_PHASE_OUT,
    FS_EC_GOOD,
    FFDHE_GENERATOR,
    FFDHE_PHASE_OUT_PRIMES,
    CIPHERS_GOOD,
    CIPHERS_SUFFICIENT,
    CIPHERS_PHASE_OUT,
)


@dataclass(frozen=True)
class TLSProtocolEvaluation:
    """
    Evaluate the accepted TLS protocols, i.e. SSL 3.0/TLS 1.1/etc.
    """

    good: List[TlsVersionEnum]
    sufficient: List[TlsVersionEnum]
    phase_out: List[TlsVersionEnum]
    bad: List[TlsVersionEnum]

    good_str: List[str]
    sufficient_str: List[str]
    phase_out_str: List[str]
    bad_str: List[str]

    @classmethod
    def from_protocols_accepted(cls, protocols_accepted: List[TlsVersionEnum]):
        good = []
        sufficient = []
        phase_out = []
        bad = []

        for protocol in protocols_accepted:
            if protocol in PROTOCOLS_GOOD:
                good.append(protocol)
            elif protocol in PROTOCOLS_SUFFICIENT:
                sufficient.append(protocol)
            elif protocol in PROTOCOLS_PHASE_OUT:
                phase_out.append(protocol)
            else:
                bad.append(protocol)

        return cls(
            good=good,
            sufficient=sufficient,
            phase_out=phase_out,
            bad=bad,
            good_str=cls._format_str(good),
            sufficient_str=cls._format_str(sufficient),
            phase_out_str=cls._format_str(phase_out),
            bad_str=cls._format_str(bad),
        )

    @staticmethod
    def _format_str(protocols: List[TlsVersionEnum]) -> List[str]:
        return [p.name.replace("_", " ", 1).replace("_", ".") for p in protocols]

    @property
    def score(self) -> scoring.Score:
        return scoring.WEB_TLS_PROTOCOLS_BAD if self.bad else scoring.WEB_TLS_PROTOCOLS_GOOD


@dataclass(frozen=True)
class TLSForwardSecrecyParameterEvaluation:
    """
    Evaluate the FS (DH/DHE/EC) params from the accepted cipher suites.
    """

    max_dh_size: Optional[int]
    max_ec_size: Optional[int]

    good_str: Set[str]
    phase_out_str: Set[str]
    bad_str: Set[str]

    @classmethod
    def from_ciphers_accepted(cls, ciphers_accepted: List[CipherSuiteAcceptedByServer]):
        good = set()
        phase_out = set()
        bad = set()

        # Evaluate according to NCSC table 4 and table 10
        for suite in _unique_unhashable(ciphers_accepted):
            key = suite.ephemeral_key
            if not key:
                continue

            if isinstance(key, EcDhEphemeralKeyInfo):
                if key.curve in FS_EC_PHASE_OUT:
                    phase_out.add(f"ECDH-{key.curve_name}")
                elif key.curve not in FS_EC_GOOD:
                    bad.add(f"ECDH-{key.curve_name}")

            if isinstance(key, DhEphemeralKeyInfo):
                # NCSC 3.3.3.1
                if key.generator == FFDHE_GENERATOR:
                    if key.prime in FFDHE_PHASE_OUT_PRIMES:
                        phase_out.add(f"DH-{key.size}")
                    else:
                        bad.add(f"DH-{key.size}")

        dh_sizes = [
            suite.ephemeral_key.size
            for suite in ciphers_accepted
            if suite.ephemeral_key and suite.ephemeral_key.type == OpenSslEvpPkeyEnum.DH
        ]
        ec_sizes = [
            suite.ephemeral_key.size
            for suite in ciphers_accepted
            if suite.ephemeral_key and suite.ephemeral_key.type == OpenSslEvpPkeyEnum.EC
        ]

        return cls(
            good_str=good,
            phase_out_str=phase_out,
            bad_str=bad,
            max_dh_size=max(dh_sizes) if dh_sizes else None,
            max_ec_size=max(ec_sizes) if ec_sizes else None,
        )

    @property
    def score(self) -> scoring.Score:
        return scoring.WEB_TLS_FS_BAD if self.bad_str else scoring.WEB_TLS_FS_GOOD


@dataclass(frozen=True)
class TLSCipherEvaluation:
    """
    Evaluate the accepted TLS ciphers (across all TLS versions).
    """

    ciphers_good: List[CipherSuite]
    ciphers_good_no_tls13: List[CipherSuite]
    ciphers_sufficient: List[CipherSuite]
    ciphers_phase_out: List[CipherSuite]
    ciphers_bad: List[CipherSuite]

    ciphers_good_str: List[str]
    ciphers_sufficient_str: List[str]
    ciphers_phase_out_str: List[str]
    ciphers_bad_str: List[str]

    @classmethod
    def from_ciphers_accepted(cls, ciphers_accepted: List[CipherSuiteAcceptedByServer]):
        ciphers_good = []
        ciphers_sufficient = []
        ciphers_phase_out = []
        ciphers_bad = []
        for suite in _unique_unhashable(ciphers_accepted):
            if suite.cipher_suite.name in CIPHERS_GOOD:
                ciphers_good.append(suite.cipher_suite)
            elif suite.cipher_suite.name in CIPHERS_SUFFICIENT:
                ciphers_sufficient.append(suite.cipher_suite)
            elif suite.cipher_suite.name in CIPHERS_PHASE_OUT:
                ciphers_phase_out.append(suite.cipher_suite)
            else:
                ciphers_bad.append(suite.cipher_suite)
        return cls(
            ciphers_good=ciphers_good,
            ciphers_good_no_tls13=[c for c in ciphers_good if c.name not in _TLS_1_3_CIPHER_SUITES],
            ciphers_sufficient=ciphers_sufficient,
            ciphers_phase_out=ciphers_phase_out,
            ciphers_bad=ciphers_bad,
            ciphers_good_str=cls._format_str(ciphers_good),
            ciphers_sufficient_str=cls._format_str(ciphers_sufficient),
            ciphers_phase_out_str=cls._format_str(ciphers_phase_out),
            ciphers_bad_str=cls._format_str(ciphers_bad),
        )

    @staticmethod
    def _format_str(suites: List[CipherSuite]) -> List[str]:
        return [f"{suite.name}" for suite in suites]

    @property
    def score(self) -> scoring.Score:
        return scoring.WEB_TLS_SUITES_BAD if self.ciphers_bad else scoring.WEB_TLS_SUITES_GOOD


@dataclass(frozen=True)
class TLSOCSPEvaluation:
    """
    Evaluate the OCSP setup, based on certificate info.
    """

    ocsp_in_cert: bool
    has_ocsp_response: bool
    ocsp_response_trusted: bool

    GOOD_STATUSES = {OcspStatus.good, OcspStatus.not_in_cert}

    @classmethod
    def from_certificate_deployments(cls, certificate_deployment: CertificateDeploymentAnalysisResult):
        leaf_cert = certificate_deployment.received_certificate_chain[0]
        try:
            aia_extension = leaf_cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            aia_value = cast(AuthorityInformationAccess, aia_extension.value)
            ocsp_access = [ad for ad in aia_value if ad.access_method == AuthorityInformationAccessOID.OCSP]
            ocsp_in_cert = len(ocsp_access) > 0
        except ExtensionNotFound:
            ocsp_in_cert = False

        has_ocsp_response = certificate_deployment.ocsp_response is not None
        ocsp_response_trusted = certificate_deployment.ocsp_response is True

        return cls(
            ocsp_in_cert=ocsp_in_cert,
            has_ocsp_response=has_ocsp_response,
            ocsp_response_trusted=ocsp_response_trusted,
        )

    @property
    def status(self) -> OcspStatus:
        if not self.ocsp_in_cert:
            return OcspStatus.not_in_cert
        if self.has_ocsp_response:
            if self.ocsp_response_trusted:
                return OcspStatus.good
            else:
                return OcspStatus.not_trusted
        return OcspStatus.ok

    @property
    def score(self) -> scoring.Score:
        return (
            scoring.WEB_TLS_OCSP_STAPLING_GOOD
            if self.status in self.GOOD_STATUSES
            else scoring.WEB_TLS_OCSP_STAPLING_BAD
        )


@dataclass(frozen=True)
class TLSRenegotiationEvaluation:
    """
    Evaluate the secure renegotiation settings per NCSC 3.4.2
    """

    supports_secure_renegotiation: bool
    client_renegotiations_success_count: int

    # What counts as "limited" per NCSC 3.4.2
    MAX_SECURE_RENEG_ATTEMPTS = 10
    # The number of attempts the scan should make
    SCAN_RENEGOTIATION_LIMIT = MAX_SECURE_RENEG_ATTEMPTS + 1

    @classmethod
    def from_session_renegotiation_scan_result(cls, session_renegotiation_scan_result: SessionRenegotiationScanResult):
        return cls(
            supports_secure_renegotiation=session_renegotiation_scan_result.supports_secure_renegotiation,
            client_renegotiations_success_count=session_renegotiation_scan_result.client_renegotiations_success_count,
        )

    @property
    def status_secure_renegotiation(self) -> bool:
        return self.supports_secure_renegotiation

    @property
    def status_client_initiated_renegotiation(self) -> TLSClientInitiatedRenegotiationStatus:
        if not self.client_renegotiations_success_count:
            return TLSClientInitiatedRenegotiationStatus.not_allowed
        if self.client_renegotiations_success_count <= self.MAX_SECURE_RENEG_ATTEMPTS:
            return TLSClientInitiatedRenegotiationStatus.allowed_with_low_limit
        return TLSClientInitiatedRenegotiationStatus.allowed_with_too_high_limit

    @property
    def score_secure_renegotiation(self) -> scoring.Score:
        return (
            scoring.WEB_TLS_SECURE_RENEG_GOOD
            if self.supports_secure_renegotiation
            else scoring.WEB_TLS_SECURE_RENEG_BAD
        )

    @property
    def score_client_initiated_renegotiation(self) -> scoring.Score:
        scores = {
            TLSClientInitiatedRenegotiationStatus.not_allowed: scoring.WEB_TLS_CLIENT_RENEG_GOOD,
            TLSClientInitiatedRenegotiationStatus.allowed_with_low_limit: scoring.WEB_TLS_CLIENT_RENEG_OK,
            TLSClientInitiatedRenegotiationStatus.allowed_with_too_high_limit: scoring.WEB_TLS_CLIENT_RENEG_BAD,
        }
        return scores[self.status_client_initiated_renegotiation]


@dataclass(frozen=True)
class KeyExchangeRSAPKCSFunctionEvaluation:
    """
    Results of support for PKCS padding for RSA per NCSC 3.3.2.1.
    NCSC table 5
    """

    status: KexRSAPKCSStatus
    score: scoring.Score


@dataclass(frozen=True)
class KeyExchangeHashFunctionEvaluation:
    """
    Results of "hash functions for key exchange" evaluation.
    NCSC 3.3.5
    """

    status: KexHashFuncStatus
    score: scoring.Score


@dataclass(frozen=True)
class TLSCipherOrderEvaluation:
    """
    Results of cipher order evaluation.
    If a violation is found, the violation attribute is a two
    item list with first the cipher preferred by the server,
    second the cipher we expected to be preferred above that.
    NCSC B2-5
    """

    violation: List[str]
    status: CipherOrderStatus
    score: scoring.Score


def _unique_unhashable(items: List[Any]) -> List[Any]:
    """
    Keep only unique items from a list of unhashable types.
    Lives here as we use it only for CipherSuite, which is
    not hashable.
    """
    result = []
    for item in items:
        if item not in result:
            result.append(item)
    return result
