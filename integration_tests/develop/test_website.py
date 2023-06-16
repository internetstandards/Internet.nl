"""Basis functionality that should always be present."""
import pytest
from playwright.sync_api import expect
from ..conftest import print_details_test_results
from .conftest import ipv6_available

INVALID_DOMAIN = "invalid-domain.example.com"

TEST_DOMAIN_EXPECTED_SCORE = 100
TEST_DOMAIN_EXPECTED_SCORE_NO_IPV6 = 61

LONG_TIMEOUT = 1000 * 3 * 60


def test_reject_invalid_domain(page, app_url):
    domain = INVALID_DOMAIN

    page.goto(app_url)

    page.locator("#web-url").fill(domain)
    page.locator("section.websitetest button").click()

    assert page.url == f"{app_url}/test-site/?invalid"


@pytest.mark.skipif(not ipv6_available(), reason="IPv6 networking not available")
def test_your_website_score_with_ipv6(page, app_url, test_domain):
    """Run "Test your website" from the frontpage and expect a decent result."""

    page.goto(app_url)

    page.locator("#web-url").fill(test_domain)
    page.locator("section.websitetest button").click()

    assert page.url == f"{app_url}/site/{test_domain}/"

    page.wait_for_url(f"{app_url}/site/{test_domain}/*/")

    score = page.locator("div.testresults-percentage")

    print_details_test_results(page)

    expect(score).to_have_attribute("data-resultscore", str(TEST_DOMAIN_EXPECTED_SCORE))


@pytest.mark.skipif(ipv6_available(), reason="IPv6 networking available")
def test_your_website_score_no_ipv6(page, app_url, test_domain):
    """Run "Test your website" from the frontpage and expect a decent result."""

    page.goto(app_url)

    page.locator("#web-url").fill(test_domain)
    page.locator("section.websitetest button").click()

    assert page.url == f"{app_url}/site/{test_domain}/"

    page.wait_for_url(f"{app_url}/site/{test_domain}/*/", timeout=LONG_TIMEOUT)

    score = page.locator("div.testresults-percentage")

    print_details_test_results(page)

    expect(score).to_have_attribute("data-resultscore", str(TEST_DOMAIN_EXPECTED_SCORE_NO_IPV6))
