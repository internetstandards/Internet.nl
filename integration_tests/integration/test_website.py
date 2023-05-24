"""Basis functionality that should always be present."""
from datetime import timedelta
import pytest
import re
from playwright.sync_api import Page, expect
from pytest_playwright import pytest_playwright
from ..conftest import print_details_test_results

INTERNETNL_APP_URL = "http://internet.test"

INVALID_DOMAIN = "invalid-domain.example.com"

TEST_DOMAIN = "target.test"
ALL_PROBES = {"ipv6", "dnssec", "tls", "appsecpriv", "rpki"}
TEST_DOMAIN_EXPECTED_SCORE = 100
# TODO: improve test environment to allow 100% score result
TEST_DOMAIN_EXPECTED_SCORE = 48

def test_reject_invalid_domain(page, app_url):
    domain = INVALID_DOMAIN

    page.goto(app_url)

    page.locator('#web-url').fill(domain)
    page.locator('section.websitetest button').click()

    assert page.url == f"{app_url}/test-site/?invalid"

def test_your_website_score(page, app_url, unique_id, test_domain=TEST_DOMAIN):
    """Run "Test your website" from the frontpage and expect a decent result."""

    test_domain = f"{unique_id}.{test_domain}"

    page.goto(app_url)

    page.locator('#web-url').fill(test_domain)
    page.locator('section.websitetest button').click()

    assert page.url == f"{app_url}/site/{test_domain}/"

    page.wait_for_url(f"{app_url}/site/{test_domain}/*/")

    score = page.locator('div.testresults-percentage')

    print_details_test_results(page)

    expect(score).to_have_attribute('data-resultscore', str(TEST_DOMAIN_EXPECTED_SCORE))

@pytest.mark.skip(reason="test environment not complete enough to allow all tests to pass")
@pytest.mark.parametrize("probe", ALL_PROBES)
def test_your_website_probe_success(page, app_url, probe, unique_id, test_domain=TEST_DOMAIN):
    test_domain = f"{unique_id}.{test_domain}"

    page.goto(f"{app_url}/site/{test_domain}/")
    page.wait_for_url(f"{app_url}/site/{test_domain}/*/")

    probe_result = page.locator(f'#site{probe}-results')
    expect(probe_result).to_have_class('passed')
