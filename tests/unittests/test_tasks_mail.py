from unittest import skip

from django.test import SimpleTestCase

import checks
from checks.models import DmarcPolicyStatus
from checks.tasks import mail
from checks.tasks.dmarc_parser import parse as dmarc_parse


class DmarcVerifySufficientPolicyTestCase(SimpleTestCase):
    def _verify(self, record, is_org_domain=False):
        parsed = dmarc_parse(record)
        status, _ = mail.dmarc_verify_sufficient_policy(parsed, is_org_domain, public_suffix_list=[])
        return status

    def test_reject_is_valid(self):
        self.assertEqual(self._verify("v=DMARC1; p=reject"), DmarcPolicyStatus.valid)

    def test_quarantine_is_valid(self):
        self.assertEqual(self._verify("v=DMARC1; p=quarantine"), DmarcPolicyStatus.valid)

    def test_none_is_insufficient(self):
        self.assertEqual(self._verify("v=DMARC1; p=none"), DmarcPolicyStatus.invalid_p_sp)

    def test_reject_with_test_mode_is_valid(self):
        """RFC 9989 `t=y` downgrades reject to quarantine; we still accept that."""
        self.assertEqual(self._verify("v=DMARC1; p=reject; t=y"), DmarcPolicyStatus.valid)

    def test_quarantine_with_test_mode_is_insufficient(self):
        """RFC 9989 `t=y` downgrades quarantine to none."""
        self.assertEqual(self._verify("v=DMARC1; p=quarantine; t=y"), DmarcPolicyStatus.invalid_p_sp)

    def test_none_with_test_mode_is_insufficient(self):
        self.assertEqual(self._verify("v=DMARC1; p=none; t=y"), DmarcPolicyStatus.invalid_p_sp)

    def test_test_mode_off_does_not_change_anything(self):
        self.assertEqual(self._verify("v=DMARC1; p=reject; t=n"), DmarcPolicyStatus.valid)
        self.assertEqual(self._verify("v=DMARC1; p=quarantine; t=n"), DmarcPolicyStatus.valid)
        self.assertEqual(self._verify("v=DMARC1; p=none; t=n"), DmarcPolicyStatus.invalid_p_sp)

    def test_org_domain_sp_takes_precedence_and_gets_downgraded(self):
        """`sp=` wins over `p=` for org domains, and the t=y downgrade
        applies to the resulting effective policy."""
        self.assertEqual(
            self._verify("v=DMARC1; p=reject; sp=quarantine; t=y", is_org_domain=True),
            DmarcPolicyStatus.invalid_p_sp,
        )

    def test_org_domain_falls_back_to_p_when_sp_absent(self):
        """For org domains without `sp=`, the `p=` value is the effective
        policy, and the t=y downgrade still applies to it."""
        self.assertEqual(
            self._verify("v=DMARC1; p=reject; t=y", is_org_domain=True),
            DmarcPolicyStatus.valid,
        )
        self.assertEqual(
            self._verify("v=DMARC1; p=quarantine; t=y", is_org_domain=True),
            DmarcPolicyStatus.invalid_p_sp,
        )

    def test_org_domain_sp_none_is_insufficient(self):
        """An explicit `sp=none` on an org domain is insufficient even
        without t=, via the `value == "none"` branch."""
        self.assertEqual(
            self._verify("v=DMARC1; p=reject; sp=none", is_org_domain=True),
            DmarcPolicyStatus.invalid_p_sp,
        )


class DmarcNonSendingPolicyRegexTestCase(SimpleTestCase):
    def test_regex_cases(self):
        """
        This tests only if the organizational record is reject for a subdomain.
        The records are already prechecked for syntax, so we don't bother here.

        """
        cases = {
            ("v=DMARC1; p=reject; sp=reject", self.assertIsNotNone),
            ("v=DMARC1; sp=reject", self.assertIsNotNone),
            ("v=DMARC1; p=reject; sp=whatever", self.assertIsNone),
            ("v=DMARC1; p=reject; other stuff with no sp", self.assertIsNotNone),
            ("v=DMARC1; p=reject", self.assertIsNotNone),
            ("v=DMARC1; p=none; sp=none", self.assertIsNone),
            ("v=DMARC1; sp=none", self.assertIsNone),
            ("v=DMARC1; p=none; sp=whatever", self.assertIsNone),
            ("v=DMARC1; p=none; other stuff with no sp", self.assertIsNone),
            ("v=DMARC1; p=none", self.assertIsNone),
        }
        for record, check in cases:
            with self.subTest(msg=record):
                check(checks.DMARC_NON_SENDING_POLICY_ORG.match(record))


@skip(reason="Todo: KeyError: 'data'")
class PublicSuffixListTestCase(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.suffix_list = mail.dmarc_get_public_suffix_list()
        # Cases taken from https://raw.githubusercontent.com/publicsuffix/list/master/tests/test_psl.txt
        # - Some are commented out because the input is not valid for the
        #   internet.nl function.
        # - If the PSL changes for some of the below domains (unlikely); the
        #   below cases need to be revisited.
        cls.cases = [
            # null input.
            ("", ""),
            # Mixed case. Not relevant input for internet.nl
            # ('COM', ''),
            # ('example.COM', 'example.com'),
            # ('WwW.example.COM', 'example.com'),
            # Leading dot. Not relevant input for internet.nl
            # ('.com', ''),
            # ('.example', ''),
            # ('.example.com', ''),
            # ('.example.example', ''),
            # Unlisted TLD.
            ("example", ""),
            ("example.example", "example.example"),
            ("b.example.example", "example.example"),
            ("a.b.example.example", "example.example"),
            # Listed, but non-Internet, TLD.
            # ('local', ''),
            # ('example.local', ''),
            # ('b.example.local', ''),
            # ('a.b.example.local', ''),
            # TLD with only 1 rule.
            ("biz", ""),
            ("domain.biz", "domain.biz"),
            ("b.domain.biz", "domain.biz"),
            ("a.b.domain.biz", "domain.biz"),
            # TLD with some 2-level rules.
            ("com", ""),
            ("example.com", "example.com"),
            ("b.example.com", "example.com"),
            ("a.b.example.com", "example.com"),
            ("uk.com", ""),
            ("example.uk.com", "example.uk.com"),
            ("b.example.uk.com", "example.uk.com"),
            ("a.b.example.uk.com", "example.uk.com"),
            ("test.ac", "test.ac"),
            # TLD with only 1 (wildcard) rule.
            ("mm", ""),
            ("c.mm", ""),
            ("b.c.mm", "b.c.mm"),
            ("a.b.c.mm", "b.c.mm"),
            # More complex TLD.
            ("jp", ""),
            ("test.jp", "test.jp"),
            ("www.test.jp", "test.jp"),
            ("ac.jp", ""),
            ("test.ac.jp", "test.ac.jp"),
            ("www.test.ac.jp", "test.ac.jp"),
            ("kyoto.jp", ""),
            ("test.kyoto.jp", "test.kyoto.jp"),
            ("ide.kyoto.jp", ""),
            ("b.ide.kyoto.jp", "b.ide.kyoto.jp"),
            ("a.b.ide.kyoto.jp", "b.ide.kyoto.jp"),
            ("c.kobe.jp", ""),
            ("b.c.kobe.jp", "b.c.kobe.jp"),
            ("a.b.c.kobe.jp", "b.c.kobe.jp"),
            ("city.kobe.jp", "city.kobe.jp"),
            ("www.city.kobe.jp", "city.kobe.jp"),
            # TLD with a wildcard rule and exceptions.
            ("ck", ""),
            ("test.ck", ""),
            ("b.test.ck", "b.test.ck"),
            ("a.b.test.ck", "b.test.ck"),
            ("www.ck", "www.ck"),
            ("www.www.ck", "www.ck"),
            # US K12.
            ("us", ""),
            ("test.us", "test.us"),
            ("www.test.us", "test.us"),
            ("ak.us", ""),
            ("test.ak.us", "test.ak.us"),
            ("www.test.ak.us", "test.ak.us"),
            ("k12.ak.us", ""),
            ("test.k12.ak.us", "test.k12.ak.us"),
            ("www.test.k12.ak.us", "test.k12.ak.us"),
            # IDN labels. Not relevant input for internet.nl
            # ('食狮.com.cn', '食狮.com.cn'),
            # ('食狮.公司.cn', '食狮.公司.cn'),
            # ('www.食狮.公司.cn', '食狮.公司.cn'),
            # ('shishi.公司.cn', 'shishi.公司.cn'),
            # ('公司.cn', ''),
            # ('食狮.中国', '食狮.中国'),
            # ('www.食狮.中国', '食狮.中国'),
            # ('shishi.中国', 'shishi.中国'),
            # ('中国', ''),
            # Same as above, but punycoded.
            ("xn--85x722f.com.cn", "xn--85x722f.com.cn"),
            ("xn--85x722f.xn--55qx5d.cn", "xn--85x722f.xn--55qx5d.cn"),
            ("www.xn--85x722f.xn--55qx5d.cn", "xn--85x722f.xn--55qx5d.cn"),
            ("shishi.xn--55qx5d.cn", "shishi.xn--55qx5d.cn"),
            ("xn--55qx5d.cn", ""),
            ("xn--85x722f.xn--fiqs8s", "xn--85x722f.xn--fiqs8s"),
            ("www.xn--85x722f.xn--fiqs8s", "xn--85x722f.xn--fiqs8s"),
            ("shishi.xn--fiqs8s", "shishi.xn--fiqs8s"),
            ("xn--fiqs8s", ""),
        ]

    def test_public_suffix_list(self):
        for domain, org_domain in self.cases:
            with self.subTest(msg=domain):
                found = mail.dmarc_find_organizational_domain(domain, self.suffix_list)
                self.assertEqual(org_domain, found)
