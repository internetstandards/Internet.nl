from django.test import SimpleTestCase

import checks
from checks.tasks import mail


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
            ('', ''),

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
            ('example', ''),
            ('example.example', 'example.example'),
            ('b.example.example', 'example.example'),
            ('a.b.example.example', 'example.example'),

            # Listed, but non-Internet, TLD.
            #('local', ''),
            #('example.local', ''),
            #('b.example.local', ''),
            #('a.b.example.local', ''),

            # TLD with only 1 rule.
            ('biz', ''),
            ('domain.biz', 'domain.biz'),
            ('b.domain.biz', 'domain.biz'),
            ('a.b.domain.biz', 'domain.biz'),

            # TLD with some 2-level rules.
            ('com', ''),
            ('example.com', 'example.com'),
            ('b.example.com', 'example.com'),
            ('a.b.example.com', 'example.com'),
            ('uk.com', ''),
            ('example.uk.com', 'example.uk.com'),
            ('b.example.uk.com', 'example.uk.com'),
            ('a.b.example.uk.com', 'example.uk.com'),
            ('test.ac', 'test.ac'),

            # TLD with only 1 (wildcard) rule.
            ('mm', ''),
            ('c.mm', ''),
            ('b.c.mm', 'b.c.mm'),
            ('a.b.c.mm', 'b.c.mm'),

            # More complex TLD.
            ('jp', ''),
            ('test.jp', 'test.jp'),
            ('www.test.jp', 'test.jp'),
            ('ac.jp', ''),
            ('test.ac.jp', 'test.ac.jp'),
            ('www.test.ac.jp', 'test.ac.jp'),
            ('kyoto.jp', ''),
            ('test.kyoto.jp', 'test.kyoto.jp'),
            ('ide.kyoto.jp', ''),
            ('b.ide.kyoto.jp', 'b.ide.kyoto.jp'),
            ('a.b.ide.kyoto.jp', 'b.ide.kyoto.jp'),
            ('c.kobe.jp', ''),
            ('b.c.kobe.jp', 'b.c.kobe.jp'),
            ('a.b.c.kobe.jp', 'b.c.kobe.jp'),
            ('city.kobe.jp', 'city.kobe.jp'),
            ('www.city.kobe.jp', 'city.kobe.jp'),

            # TLD with a wildcard rule and exceptions.
            ('ck', ''),
            ('test.ck', ''),
            ('b.test.ck', 'b.test.ck'),
            ('a.b.test.ck', 'b.test.ck'),
            ('www.ck', 'www.ck'),
            ('www.www.ck', 'www.ck'),

            # US K12.
            ('us', ''),
            ('test.us', 'test.us'),
            ('www.test.us', 'test.us'),
            ('ak.us', ''),
            ('test.ak.us', 'test.ak.us'),
            ('www.test.ak.us', 'test.ak.us'),
            ('k12.ak.us', ''),
            ('test.k12.ak.us', 'test.k12.ak.us'),
            ('www.test.k12.ak.us', 'test.k12.ak.us'),

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
            ('xn--85x722f.com.cn', 'xn--85x722f.com.cn'),
            ('xn--85x722f.xn--55qx5d.cn', 'xn--85x722f.xn--55qx5d.cn'),
            ('www.xn--85x722f.xn--55qx5d.cn', 'xn--85x722f.xn--55qx5d.cn'),
            ('shishi.xn--55qx5d.cn', 'shishi.xn--55qx5d.cn'),
            ('xn--55qx5d.cn', ''),
            ('xn--85x722f.xn--fiqs8s', 'xn--85x722f.xn--fiqs8s'),
            ('www.xn--85x722f.xn--fiqs8s', 'xn--85x722f.xn--fiqs8s'),
            ('shishi.xn--fiqs8s', 'shishi.xn--fiqs8s'),
            ('xn--fiqs8s', ''),
        ]

    def test_public_suffix_list(self):
        for domain, org_domain in self.cases:
            with self.subTest(msg=domain):
                found = mail.dmarc_find_organizational_domain(domain, self.suffix_list)
                self.assertEqual(org_domain, found)
