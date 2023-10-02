"""Basis functionality that should always be present."""
import pytest
import re
from playwright.sync_api import expect
from ..conftest import print_details_test_results

INVALID_DOMAIN = "invalid-domain.example.com"

ALL_PROBES = {"ipv6", "dnssec", "tls", "appsecpriv", "rpki"}
TEST_DOMAIN_EXPECTED_SCORE = 100

# maximum timeout is de default setting for maximum test duration + default timeout
MAX_TIMEOUT = 1000 * (200 + 30)


def test_reject_invalid_domain(page, app_url):
    domain = INVALID_DOMAIN

    page.goto(app_url)

    page.locator("#web-url").fill(domain)
    page.locator("section.websitetest button").click()

    assert page.url == f"{app_url}/test-site/?invalid"


def test_your_website_score(page, app_url, test_domain):
    """Run "Test your website" from the frontpage and expect a decent result."""

    page.goto(app_url)

    page.locator("#web-url").fill(test_domain)
    page.locator("section.websitetest button").click()

    assert page.url == f"{app_url}/site/{test_domain}/"

    page.wait_for_url(f"{app_url}/site/{test_domain}/*/")

    score = page.locator("div.testresults-percentage")

    print_details_test_results(page)

    expect(score).to_have_attribute("data-resultscore", str(TEST_DOMAIN_EXPECTED_SCORE))


@pytest.mark.parametrize("probe", ALL_PROBES)
def test_your_website_probe_success(page, app_url, test_domain, probe):
    page.goto(f"{app_url}/site/{test_domain}/")
    # make sure the test has been started
    page.get_by_text(f"Website test: {test_domain}")
    # make sure the test is completed
    page.wait_for_url(f"{app_url}/site/{test_domain}/*/")

    probe_result = page.locator(f"#site{probe}-results")
    expect(probe_result).to_have_class(re.compile(r"passed"))


@pytest.mark.parametrize(
    "test_domain,expected_score",
    [
        # 100%
        ("internet.nl", 100),
        ("example.nl", 100),
        # https://github.com/internetstandards/Internet.nl/issues/1061
        # IPv6 only
        ("forfun.net", 100),
        ("ipv6.google.com", 65),  # no DNSSEC, bad HTTPS
        ("ipv6.internet.nl", 97),  # no HTTPS redirect
        # bogus DNSSEC
        ("servfail.nl", 61),
        ("brokendnssec.net", 15),
        ("ok.bogussig.ok.bad-dnssec.wb.sidnlabs.nl", 58),
        # wrong DANE
        ("badhash.dane.huque.com", 68),
        # TLS issues
        ("expired.badssl.com", 47),
        ("wrong.host.badssl.com", 47),
        ("self-signed.badssl.com", 47),
        ("untrusted-root.badssl.com", 47),
        ("revoked.badssl.com", 47),
        ("pinning-test.badssl.com", 49),
        # invalid RPKI
        ("invalid.rpki.isbgpsafeyet.com", 48),
    ],
)
def test_your_website_score_known_scores(page, app_url, test_domain, expected_score):
    """Run "Test your website" on a list of known domains with a known score."""

    page.goto(app_url)

    page.locator("#web-url").fill(test_domain)
    page.locator("section.websitetest button").click()

    assert page.url == f"{app_url}/site/{test_domain}/"

    page.wait_for_url(f"{app_url}/site/{test_domain}/*/", timeout=MAX_TIMEOUT)

    score = page.locator("div.testresults-percentage")

    print_details_test_results(page)

    assert score.get_attribute("data-resultscore") == str(expected_score)
