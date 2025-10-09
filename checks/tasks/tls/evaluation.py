from dataclasses import dataclass
from typing import List, Optional, Any, Set

from nassl.ephemeral_key_info import EcDhEphemeralKeyInfo, DhEphemeralKeyInfo, OpenSslEvpPkeyEnum
from sslyze import TlsVersionEnum, CipherSuiteAcceptedByServer, CipherSuite
from sslyze.plugins.openssl_cipher_suites.cipher_suites import _TLS_1_3_CIPHER_SUITES

from checks import scoring
from checks.models import KexHashFuncStatus, CipherOrderStatus
from checks.tasks.tls.tls_constants import (
    PROTOCOLS_GOOD,
    PROTOCOLS_SUFFICIENT,
    PROTOCOLS_PHASE_OUT,
    FS_ECDH_MIN_KEY_SIZE,
    FS_EC_PHASE_OUT,
    FS_EC_GOOD,
    FS_DH_MIN_KEY_SIZE,
    FFDHE_GENERATOR,
    FFDHE2048_PRIME,
    FFDHE_SUFFICIENT_PRIMES,
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
                if key.size < FS_ECDH_MIN_KEY_SIZE:
                    bad.add(f"ECDH-{key.size}")
                if key.curve in FS_EC_PHASE_OUT:
                    phase_out.add(f"ECDH-{key.curve_name}")
                elif key.curve not in FS_EC_GOOD:
                    bad.add(f"ECDH-{key.curve_name}")

            if isinstance(key, DhEphemeralKeyInfo):
                if key.size < FS_DH_MIN_KEY_SIZE:
                    bad.add(f"DH-{key.size}")
                # NCSC table 10
                if key.generator == FFDHE_GENERATOR:
                    if key.prime == FFDHE2048_PRIME:
                        phase_out.add("FFDHE-2048")
                    elif key.prime not in FFDHE_SUFFICIENT_PRIMES:
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
class KeyExchangeHashFunctionEvaluation:
    """
    Results of "hash functions for key exchange" evaluation.
    NCSC table 5
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
