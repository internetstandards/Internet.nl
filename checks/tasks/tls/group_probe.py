"""Detect weak TLS 1.2 supported groups that ordinary cipher probes can miss.

Cipher probing only records the one key-exchange group negotiated for each
cipher. Offer weak groups separately to find servers which also accept them,
without SSLyze's per-curve network probes.
"""

from dataclasses import replace

from nassl._nassl import OpenSSLError
from nassl.ephemeral_key_info import EcDhEphemeralKeyInfo, OpenSslEcNidEnum
from nassl.ssl_client import ClientCertificateRequested
from sslyze import TlsVersionEnum
from sslyze.errors import ConnectionToServerFailed, ServerTlsConfigurationNotSupported, TlsHandshakeTimedOut
from sslyze.server_connectivity import ServerConnectivityInfo, enable_ecdh_cipher_suites

from checks.tasks.tls.tls_constants import FS_EC_GOOD, FS_EC_PHASE_OUT
from internetnl import log


def _accepted_weak_group(server_info: ServerConnectivityInfo, candidates: set[OpenSslEcNidEnum]) -> str | None:
    """One TLS 1.2 handshake offering only groups in the given category.

    Check the *negotiated* ephemeral group rather than treating a successful
    handshake as proof: servers can choose a different key-exchange method.
    """
    if not candidates:
        return None

    connection = None
    try:
        connection = server_info.get_preconfigured_tls_connection(
            override_tls_version=TlsVersionEnum.TLS_1_2, should_use_legacy_openssl=False
        )
        enable_ecdh_cipher_suites(TlsVersionEnum.TLS_1_2, connection.ssl_client)

        # OpenSSL may not accept every legacy curve. Filter locally first,
        # rather than having one unsupported curve invalidate the whole offer.
        available = []
        for curve in sorted(candidates, key=lambda curve: curve.value):
            try:
                connection.ssl_client.set_groups([curve])
                available.append(curve)
            except (OpenSSLError, ValueError):
                continue
        if not available:
            return None

        connection.ssl_client.set_groups(available)
        try:
            connection.connect()
        except ClientCertificateRequested:
            # The server's key exchange has already been negotiated.
            pass
        key = connection.ssl_client.get_ephemeral_key()
        if isinstance(key, EcDhEphemeralKeyInfo) and key.curve in available:
            return f"ECDH-{key.curve_name}"
    except (ConnectionToServerFailed, ServerTlsConfigurationNotSupported, TlsHandshakeTimedOut, OpenSSLError, ValueError) as exc:
        log.debug(f"TLS 1.2 weak-group probe on {server_info.server_location.hostname} failed: {exc}")
    finally:
        if connection is not None:
            connection.close()
    return None


def probe_weak_tls12_groups(
    server_info: ServerConnectivityInfo, supported_tls_versions: list[TlsVersionEnum]
) -> tuple[set[str], set[str]]:
    """Find bad and phase-out TLS 1.2 ECDHE groups with at most two handshakes.

    TLS 1.3 FFDHE and hybrid/PQC groups require separate support in nassl;
    OpenSslEcNidEnum only contains the EC groups applicable here.
    """
    if TlsVersionEnum.TLS_1_2 not in supported_tls_versions:
        return set(), set()

    available_nids = OpenSslEcNidEnum.get_supported_by_ssl_client()
    phase_out = available_nids.intersection(FS_EC_PHASE_OUT)
    bad = available_nids.difference(FS_EC_GOOD).difference(FS_EC_PHASE_OUT)
    bad_group = _accepted_weak_group(server_info, bad)
    phase_out_group = _accepted_weak_group(server_info, phase_out)
    return ({bad_group} if bad_group else set(), {phase_out_group} if phase_out_group else set())


def include_weak_tls12_groups(fs_evaluation, server_info, supported_tls_versions):
    """Augment negotiated cipher findings without changing existing scoring rules."""
    bad, phase_out = probe_weak_tls12_groups(server_info, supported_tls_versions)
    return replace(
        fs_evaluation,
        bad_str=fs_evaluation.bad_str | bad,
        phase_out_str=fs_evaluation.phase_out_str | phase_out,
    )
