from django.test import SimpleTestCase

from checks import scoring
from checks.tasks import http_headers

# Set this to true for more information per test. Then you probably want to run
# with a specific test only like:
# ./manage.py test tests.unittests.test_tasks_http_headers..HeaderCheckerContentSecurityPolicyTestCase.test_no_default_src
DEBUG = False


class HeaderCheckerContentSecurityPolicyTestCase(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.checker = http_headers.HeaderCheckerContentSecurityPolicy()
        cls.score = 'content_security_policy_score'
        cls.enabled = 'content_security_policy_enabled'

    def setUp(self):
        self.results = self.checker.get_positive_values()
        self.domain = 'internet.nl'

    def _checker_check(self, headers):
        self.checker.check(headers, self.results, self.domain)
        if DEBUG:
            print(self.checker.result)

    def _is_good(self, headers):
        self._checker_check(headers)
        self.assertEqual(self.results[self.enabled], True)
        self.assertEqual(
            self.results[self.score],
            scoring.WEB_APPSECPRIV_CONTENT_SECURITY_POLICY_GOOD)

    def _is_good_and_parsed(self, headers, directive):
        self._checker_check(headers)
        self.assertEqual(self.results[self.enabled], True)
        self.assertEqual(
            self.results[self.score],
            scoring.WEB_APPSECPRIV_CONTENT_SECURITY_POLICY_GOOD)
        self.assertTrue(directive in self.checker.parsed)

    def _is_good_and_not_parsed(self, headers, directive):
        self._checker_check(headers)
        self.assertEqual(self.results[self.enabled], True)
        self.assertEqual(
            self.results[self.score],
            scoring.WEB_APPSECPRIV_CONTENT_SECURITY_POLICY_GOOD)
        self.assertTrue(directive not in self.checker.parsed)

    def _is_bad(self, headers):
        self._checker_check(headers)
        self.assertEqual(self.results[self.enabled], False)
        self.assertEqual(
            self.results[self.score],
            scoring.WEB_APPSECPRIV_CONTENT_SECURITY_POLICY_BAD)

    def _is_bad_and_parsed(self, headers, directive):
        self._checker_check(headers)
        self.assertEqual(self.results[self.enabled], False)
        self.assertEqual(
            self.results[self.score],
            scoring.WEB_APPSECPRIV_CONTENT_SECURITY_POLICY_BAD)
        self.assertTrue(directive in self.checker.parsed)

    def test_no_value(self):
        headers = ""
        self._is_bad(headers)

    def test_smallest_valid_header_with_self(self):
        headers = "default-src 'self'; frame-ancestors 'self'"
        self._is_good(headers)

    def test_smallest_valid_header_with_none(self):
        headers = "default-src 'none'; frame-ancestors 'none'"
        self._is_good(headers)

    def test_no_default_src(self):
        headers = "frame-ancestors 'none'"
        self._is_bad(headers)

    def test_no_frame_ancestors(self):
        headers = "default-src 'none'"
        self._is_bad(headers)

    def test_unsafe_inline(self):
        headers = "default-src 'self'; frame-ancestors 'self', style-src 'unsafe-inline'"
        self._is_bad(headers)

    def test_unsafe_eval(self):
        headers = "default-src 'self'; frame-ancestors 'self', style-src 'unsafe-eval'"
        self._is_bad(headers)

    def test_unsafe_hashes(self):
        headers = "default-src 'self'; frame-ancestors 'self', style-src 'unsafe-hashes'"
        self._is_bad(headers)

    def test_default_src_1(self):
        headers = "default-src internet.nl; frame-ancestors 'self'"
        self._is_bad(headers)

    def test_default_src_2(self):
        headers = "default-src 'self' https:; frame-ancestors 'self'"
        self._is_good(headers)

    def test_default_src_3(self):
        headers = "default-src 'self' 'report_sample'; frame-ancestors 'self'"
        self._is_good(headers)

    def test_default_src_4(self):
        headers = "default-src 'self' internet.nl; frame-ancestors 'self'"
        self._is_good(headers)

    def test_default_src_5(self):
        headers = "default-src 'self' internet.nl *.internet.nl; frame-ancestors 'self'"
        self._is_good(headers)

    def test_default_src_6(self):
        headers = "default-src 'self' internet.nl *.internet.nl www.internet.nl; frame-ancestors 'self'"
        self._is_good(headers)

    def test_default_src_7(self):
        headers = "default-src 'self' internet.nl *.internet.nl internet.com; frame-ancestors 'self'"
        self._is_bad(headers)

    def test_default_src_8(self):
        headers = "default-src 'self' www.internet.nl; frame-ancestors 'self'"
        self._is_good(headers)

    def test_default_src_9(self):
        headers = "default-src 'self' www.internet.nl; frame-ancestors 'self'"
        self._is_good(headers)

    def test_default_src_10(self):
        headers = "default-src 'self' nl *.nl www.internet.nl internet.com; frame-ancestors 'self'"
        self._is_bad(headers)

    def test_default_src_11(self):
        headers = "default-src 'self' www.internet.nl; frame-ancestors 'self'"
        self._is_good(headers)

    def test_default_src_12(self):
        headers = "default-src 'self' *.internet.nl; frame-ancestors 'self'"
        self._is_good(headers)

    def test_default_src_13(self):
        headers = "default-src 'self' http:; frame-ancestors 'self'"
        self._is_bad(headers)

    def test_default_src_14(self):
        headers = "default-src 'self' somethingelse; frame-ancestors 'self'"
        self._is_bad(headers)

    def test_http_1(self):
        headers = "default-src 'self'; frame-ancestors 'self', style-src http://adfadf.com/asdfh"
        self._is_bad(headers)

    def test_http_2(self):
        headers = "default-src 'self'; frame-ancestors 'self', style-src http:"
        self._is_bad(headers)

    def test_https_1(self):
        headers = "default-src 'self'; frame-ancestors 'self', style-src https:"
        self._is_good(headers)

    def test_https_2(self):
        headers = "default-src 'self'; frame-ancestors 'self', style-src https://whatever.com:443/afsdf"
        self._is_good(headers)

    def test_https_3(self):
        headers = "default-src 'self'; frame-ancestors 'self', style-src https://[ipv6:address]:443/afsdf"
        self._is_good(headers)

    def test_star_for_port(self):
        headers = "default-src 'self'; frame-ancestors 'self', style-src https://[ipv6:address]:*/afsdf"
        self._is_good(headers)

    def test_data_1(self):
        headers = "default-src 'self'; frame-ancestors 'self', object-src data:"
        self._is_bad(headers)

    def test_data_2(self):
        headers = "default-src 'self'; frame-ancestors 'self', script-src data:"
        self._is_bad(headers)

    def test_star_scheme_1(self):
        headers = "default-src 'self'; frame-ancestors 'self', style-src *://whatever.com:443/something"
        self._is_bad(headers)

    def test_star_scheme_2(self):
        headers = "default-src 'self'; frame-ancestors 'self', style-src *://[ipv6:address:fasd]/something"
        self._is_bad(headers)

    def test_star_host_1(self):
        headers = "default-src 'self'; frame-ancestors 'self', style-src *"
        self._is_bad(headers)

    def test_star_host_2(self):
        headers = "default-src 'self'; frame-ancestors 'self', frame-src *"
        self._is_bad(headers)

    def test_star_host_3(self):
        headers = "default-src 'self'; frame-ancestors 'self', frame-src https://*"
        self._is_bad(headers)

    def test_star_host_4(self):
        headers = "default-src 'self'; frame-ancestors 'self', frame-src https://*:443/"
        self._is_bad(headers)

    def test_star_host_5(self):
        headers = "default-src 'self'; frame-ancestors 'self', frame-src https://*:443"
        self._is_bad(headers)

    def test_star_host_6(self):
        headers = "default-src 'self'; frame-ancestors 'self', frame-src *:443"
        self._is_bad(headers)

    def test_127001_host_1(self):
        headers = "default-src 'self'; frame-ancestors 'self', frame-src 127.0.0.1"
        self._is_bad(headers)

    def test_127001_host_2(self):
        headers = "default-src 'self'; frame-ancestors 'self', frame-src https://127.0.0.1"
        self._is_bad(headers)

    def test_127001_host_3(self):
        headers = "default-src 'self'; frame-ancestors 'self', frame-src https://127.0.0.1:443/"
        self._is_bad(headers)

    def test_127001_host_4(self):
        headers = "default-src 'self'; frame-ancestors 'self', frame-src https://127.0.0.1:443"
        self._is_bad(headers)

    def test_127001_host_5(self):
        headers = "default-src 'self'; frame-ancestors 'self', frame-src 127.0.0.1:443"
        self._is_bad(headers)

    def test_missing_frame_ancestors(self):
        headers = "default-src 'self'; style-src https:"
        self._is_bad(headers)

    def test_missing_frame_ancestors_syntax_error(self):
        headers = "default-src 'self'; frame-ancestors self"
        self._is_bad(headers)

    def test_wrong_frame_source(self):
        headers = "default-src 'self'; frame-ancestors 'self'; frame-src http:"
        self._is_bad(headers)

    def test_two_headers(self):
        headers = "default-src 'self'; frame-ancestors https:, frame-ancestors 'none'"
        self._is_good(headers)

    def test_syntax_trusted_types_1(self):
        headers = "default-src 'self'; frame-ancestors 'none', trusted-types"
        self._is_good_and_parsed(headers, 'trusted-types')

    def test_syntax_trusted_types_2(self):
        headers = "default-src 'self'; frame-ancestors 'none', trusted-types 'none'"
        self._is_good_and_parsed(headers, 'trusted-types')

    def test_syntax_trusted_types_3(self):
        headers = "default-src 'self'; frame-ancestors 'none', trusted-types asdfad"
        self._is_good_and_parsed(headers, 'trusted-types')

    def test_syntax_trusted_types_4(self):
        headers = "default-src 'self'; frame-ancestors 'none', trusted-types asdfad asdfd"
        self._is_good_and_parsed(headers, 'trusted-types')

    def test_syntax_trusted_types_5(self):
        headers = "default-src 'self'; frame-ancestors 'none', trusted-types asdfad asdfd 'allow-duplicates'"
        self._is_good_and_parsed(headers, 'trusted-types')

    def test_syntax_trusted_types_6(self):
        headers = "default-src 'self'; frame-ancestors 'none', trusted-types asdfad * 'allow-duplicates'"
        self._is_good_and_parsed(headers, 'trusted-types')

    def test_syntax_trusted_types_7(self):
        headers = "default-src 'self'; frame-ancestors 'none', trusted-types * asdfad 'allow-duplicates'"
        self._is_good_and_parsed(headers, 'trusted-types')

    def test_syntax_trusted_types_8(self):
        headers = "default-src 'self'; frame-ancestors 'none', trusted-types asdfad 'allow-duplicates'"
        self._is_good_and_not_parsed(headers, 'trusted-types')

    def test_syntax_upgrade_insecure_requests_1(self):
        headers = "default-src 'self'; frame-ancestors 'none', upgrade-insecure-requests"
        self._is_good_and_parsed(headers, 'upgrade-insecure-requests')

    def test_syntax_upgrade_insecure_requests_2(self):
        headers = "default-src 'self'; frame-ancestors 'none', upgrade-insecure-requests adfad"
        self._is_good_and_not_parsed(headers, 'upgrade-insecure-requests')

    def test_host_source_1(self):
        headers = "default-src 'self'; frame-ancestors 'none', style-src https://fas.com:443"
        self._is_good_and_parsed(headers, 'style-src')

    def test_host_source_2(self):
        headers = "default-src 'self'; frame-ancestors 'none', style-src fas.com:443"
        self._is_good_and_parsed(headers, 'style-src')

    def test_host_source_3(self):
        headers = "default-src 'self'; frame-ancestors 'none', style-src fas.com"
        self._is_good_and_parsed(headers, 'style-src')

    def test_scheme_source_1(self):
        headers = "default-src 'self'; frame-ancestors 'none', style-src https:"
        self._is_good_and_parsed(headers, 'style-src')

    def test_scheme_source_2(self):
        headers = "default-src 'self'; frame-ancestors 'none', style-src http:"
        self._is_bad_and_parsed(headers, 'style-src')

    def test_scheme_source_3(self):
        headers = "default-src 'self'; frame-ancestors 'none', style-src fasdf:"
        self._is_good_and_not_parsed(headers, 'style-src')

    def test_other_source_nonce_1(self):
        headers = "default-src 'self'; frame-ancestors 'none', style-src 'nonce-fdasdfas5678589+5346/sfdg'"
        self._is_good_and_parsed(headers, 'style-src')

    def test_other_source_nonce_2(self):
        headers = "default-src 'self'; frame-ancestors 'none', style-src 'nonce-fdasdfas5678589+5346/sfdg=='"
        self._is_good_and_parsed(headers, 'style-src')

    def test_other_source_nonce_3(self):
        headers = "default-src 'self'; frame-ancestors 'none', style-src 'nonce-fdasdfas56=78589+5346/sfdg=='"
        self._is_good_and_not_parsed(headers, 'style-src')

    def test_other_source_nonce_4(self):
        headers = "default-src 'self'; frame-ancestors 'none', style-src 'nonce-fdasdfas56*78589+5346/sfdg=='"
        self._is_good_and_not_parsed(headers, 'style-src')

    def test_other_source_hash_1(self):
        headers = "default-src 'self'; frame-ancestors 'none', style-src 'sha256-fdasdfas5678589+5346/sfdg=='"
        self._is_good_and_parsed(headers, 'style-src')

    def test_other_source_hash_2(self):
        headers = "default-src 'self'; frame-ancestors 'none', style-src 'sha384-fdasdfas5678589+5346/sfdg=='"
        self._is_good_and_parsed(headers, 'style-src')

    def test_other_source_hash_3(self):
        headers = "default-src 'self'; frame-ancestors 'none', style-src 'sha512-fdasdfas5678589+5346/sfdg=='"
        self._is_good_and_parsed(headers, 'style-src')

    def test_other_source_hash_4(self):
        headers = "default-src 'self'; frame-ancestors 'none', style-src 'sha513-fdasdfas5678589+5346/sfdg=='"
        self._is_good_and_not_parsed(headers, 'style-src')
