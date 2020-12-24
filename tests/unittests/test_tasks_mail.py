from django.test import SimpleTestCase

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
                check(mail.DMARC_NON_SENDING_POLICY_ORG.match(record))
