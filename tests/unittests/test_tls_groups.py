"""Focused regression tests for the TLS supported-group probes (issue #2099)."""
from dataclasses import dataclass
from unittest import TestCase
from unittest.mock import MagicMock, patch

from nassl.ephemeral_key_info import EcDhEphemeralKeyInfo, OpenSslEcNidEnum, OpenSslEvpPkeyEnum
from sslyze import TlsVersionEnum

from checks.tasks.tls.group_probe import include_weak_tls12_groups, probe_weak_tls12_groups


class WeakTlsGroupsTests(TestCase):
    def setUp(self):
        self.server = MagicMock()
        self.server.server_location.hostname = "example.test"
        self.curve = OpenSslEcNidEnum.SECP192R1  # Bad per NCSC
        self.phase_out_curve = OpenSslEcNidEnum.SECP224R1

    @staticmethod
    def ephemeral(curve):
        return EcDhEphemeralKeyInfo(type=OpenSslEvpPkeyEnum.EC, size=192, public_bytes=bytearray(), curve=curve)

    def connections(self, *keys):
        mock_connections = []
        for key in keys:
            conn = MagicMock()
            conn.ssl_client.get_ephemeral_key.return_value = key
            mock_connections.append(conn)
        self.server.get_preconfigured_tls_connection.side_effect = mock_connections
        return mock_connections

    @patch("checks.tasks.tls.group_probe.enable_ecdh_cipher_suites")
    def test_tls13_only_does_not_attempt_tls12_connection(self, _enable):
        self.assertEqual(probe_weak_tls12_groups(self.server, [TlsVersionEnum.TLS_1_3]), (set(), set()))
        self.server.get_preconfigured_tls_connection.assert_not_called()

    @patch("checks.tasks.tls.group_probe.enable_ecdh_cipher_suites")
    def test_bad_group_found_even_if_regular_cipher_probing_used_good_group(self, _enable):
        bad_conn, phase_conn = self.connections(self.ephemeral(self.curve), None)
        bad, phase_out = probe_weak_tls12_groups(self.server, [TlsVersionEnum.TLS_1_3, TlsVersionEnum.TLS_1_2])
        self.assertEqual(bad, {"ECDH-secp192r1"})
        self.assertEqual(phase_out, set())
        self.assertIn(self.curve, bad_conn.ssl_client.set_groups.call_args.args[0])
        self.assertNotIn(OpenSslEcNidEnum.SECP256R1, bad_conn.ssl_client.set_groups.call_args.args[0])
        self.assertEqual(phase_conn.ssl_client.set_groups.call_args.args[0], [self.phase_out_curve])
        self.assertEqual(self.server.get_preconfigured_tls_connection.call_count, 2)
        bad_conn.close.assert_called_once()
        phase_conn.close.assert_called_once()

    @patch("checks.tasks.tls.group_probe.enable_ecdh_cipher_suites")
    def test_both_categories_are_reported_separately(self, _enable):
        self.connections(self.ephemeral(self.curve), self.ephemeral(self.phase_out_curve))
        bad, phase_out = probe_weak_tls12_groups(self.server, [TlsVersionEnum.TLS_1_2])
        self.assertEqual(bad, {"ECDH-secp192r1"})
        self.assertEqual(phase_out, {"ECDH-secp224r1"})

    @patch("checks.tasks.tls.group_probe.enable_ecdh_cipher_suites")
    def test_rejected_handshakes_are_not_treated_as_weak_group_support(self, _enable):
        bad_conn, phase_conn = self.connections(self.ephemeral(self.curve), self.ephemeral(self.phase_out_curve))
        bad_conn.connect.side_effect = ValueError("handshake rejected")
        phase_conn.connect.side_effect = ValueError("handshake rejected")
        self.assertEqual(probe_weak_tls12_groups(self.server, [TlsVersionEnum.TLS_1_2]), (set(), set()))
        bad_conn.close.assert_called_once()
        phase_conn.close.assert_called_once()

    @patch("checks.tasks.tls.group_probe.enable_ecdh_cipher_suites")
    def test_accepted_unrelated_group_does_not_create_false_positive(self, _enable):
        self.connections(self.ephemeral(OpenSslEcNidEnum.SECP256R1), None)
        self.assertEqual(probe_weak_tls12_groups(self.server, [TlsVersionEnum.TLS_1_2]), (set(), set()))

    @patch("checks.tasks.tls.group_probe.enable_ecdh_cipher_suites")
    def test_connection_setup_failure_does_not_break_scan(self, _enable):
        self.server.get_preconfigured_tls_connection.side_effect = ValueError("unsupported TLS config")
        self.assertEqual(probe_weak_tls12_groups(self.server, [TlsVersionEnum.TLS_1_2]), (set(), set()))

    @patch("checks.tasks.tls.group_probe.enable_ecdh_cipher_suites")
    def test_unavailable_curves_are_filtered_before_handshake(self, _enable):
        bad_conn, phase_conn = self.connections(self.ephemeral(self.curve), None)
        original_set_groups = bad_conn.ssl_client.set_groups
        def set_groups(curves):
            if curves == [OpenSslEcNidEnum.SECP256K1]:
                raise ValueError("group unavailable")
            return None
        original_set_groups.side_effect = set_groups
        bad, phase_out = probe_weak_tls12_groups(self.server, [TlsVersionEnum.TLS_1_2])
        self.assertEqual(bad, {"ECDH-secp192r1"})
        self.assertEqual(phase_out, set())
        self.assertNotIn(OpenSslEcNidEnum.SECP256K1, original_set_groups.call_args.args[0])
        bad_conn.close.assert_called_once()
        phase_conn.close.assert_called_once()

    @patch("checks.tasks.tls.group_probe.enable_ecdh_cipher_suites")
    def test_existing_findings_preserved_in_merged_result(self, _enable):
        self.connections(self.ephemeral(self.curve), self.ephemeral(self.phase_out_curve))

        @dataclass(frozen=True)
        class Evaluation:
            bad_str: set[str]
            phase_out_str: set[str]

        original = Evaluation(bad_str={"DH-1024"}, phase_out_str=set())
        merged = include_weak_tls12_groups(original, self.server, [TlsVersionEnum.TLS_1_2])
        self.assertEqual(original.bad_str, {"DH-1024"})
        self.assertEqual(merged.bad_str, {"DH-1024", "ECDH-secp192r1"})
        self.assertEqual(merged.phase_out_str, {"ECDH-secp224r1"})
