import pytest

from checks.models import SpfPolicyStatus
from checks.tasks.mail import spf_check_policy


@pytest.mark.skip(reason="Other responses have not yet been mocked.")
def test_spf_check_policy():
    """
    On dev.internet.nl there there are SPF max_dns_lookups, that are not part of internet.nl results. This testcase
    helps testing that this is going right. This is a live testcase for debugging and therefore disabled in the test
    suite. This code should be tested with responses we know in advance.
    """

    spf_record = (
        "v=spf1 a mx ip4:178.18.134.219 ip4:178.18.134.202 ip4:89.146.58.102 ip4:185.217.208.76 "
        "include:sendgrid.net include:spf.mailcampaigns.nl include:spf.wearehostingyou.com "
        "include:emsd1.com include:spf.afas.online -all"
    )
    status, score, left_lookups = spf_check_policy("nac.nl", spf_record, policy_records=[])

    assert status == SpfPolicyStatus.max_dns_lookups
    assert score == 2

    # be wrong intentionally to see more debug logging.
    assert left_lookups == 1
