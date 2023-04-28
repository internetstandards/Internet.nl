"""Basis functionality that should always be present."""
from datetime import timedelta
import pytest
import re
from playwright.sync_api import Page, expect
from pytest_playwright import pytest_playwright

INTERNETNL_APP_URL = "http://internet.nl"

INVALID_DOMAIN = "invalid-domain.example.com"

TEST_DOMAIN = "test-target.internet.nl"
ALL_PROBES = {"ipv6", "dnssec", "tls", "appsecpriv", "rpki"}
TEST_DOMAIN_EXPECTED_SCORE = 100
# TODO: improve test environment to allow 100% score result
TEST_DOMAIN_EXPECTED_SCORE = 48

TEST_EMAIL = "test-target.internet.nl"
ALL_EMAIL_PROBES = {"ipv6", "dnssec", "tls", "auth", "rpki"}
TEST_EMAIL_EXPECTED_SCORE = 100
# TODO: improve test environment to allow 100% score result
TEST_EMAIL_EXPECTED_SCORE = 17

ALL_CONNECTION_PROBES = {"ipv6", "resolver"}
TEST_CONNECTION_EXPECTED_SCORE = 100.0
# TODO: improve test environment to allow 100% score result
TEST_CONNECTION_EXPECTED_SCORE = 50.0

FOOTER_TEXT = "Internet.nl is an initiative of the Internet community and the Dutch"

def test_index_http_ok(page):
    response = page.request.get(INTERNETNL_APP_URL)
    expect(response).to_be_ok()

def test_index_footer_text_present(page):
    page.goto(INTERNETNL_APP_URL)
    footer = page.locator("#footer")

    expect(footer).to_have_text(re.compile(FOOTER_TEXT))

def test_reject_invalid_domain(page):
    domain = INVALID_DOMAIN

    page.goto(INTERNETNL_APP_URL)

    page.locator('#web-url').fill(domain)
    page.locator('section.websitetest button').click()

    assert page.url == f"{INTERNETNL_APP_URL}/test-site/?invalid"

def test_your_website_score(page, unique_id, test_domain=TEST_DOMAIN):
    """Run "Test your website" from the frontpage and expect a decent result."""

    test_domain = f"{unique_id}.{test_domain}"

    page.goto(INTERNETNL_APP_URL)

    page.locator('#web-url').fill(test_domain)
    page.locator('section.websitetest button').click()

    assert page.url == f"{INTERNETNL_APP_URL}/site/{test_domain}/"

    page.wait_for_url(f"{INTERNETNL_APP_URL}/site/{test_domain}/*/")

    score = page.locator('div.testresults-percentage')
    expect(score).to_have_attribute('data-resultscore', str(TEST_DOMAIN_EXPECTED_SCORE))

@pytest.mark.xfail(raises=AssertionError, reason="test environment not complete enough to allow all tests to pass")
@pytest.mark.parametrize("probe", ALL_PROBES)
def test_your_website_probe_success(page, probe, unique_id, test_domain=TEST_DOMAIN):
    test_domain = f"{unique_id}.{test_domain}"

    page.goto(f"{INTERNETNL_APP_URL}/site/{test_domain}/")
    page.wait_for_url(f"{INTERNETNL_APP_URL}/site/{test_domain}/*/")

    probe_result = page.locator(f'#site{probe}-results')
    expect(probe_result).to_have_class('passed')


def test_your_email_score(page, test_email=TEST_EMAIL):
    """Runs the 'Test your email' and expects a decent result."""

    page.goto(INTERNETNL_APP_URL)

    page.locator('#mail-url').fill(test_email)
    page.locator('section.emailtest button').click()

    assert page.url == f"{INTERNETNL_APP_URL}/mail/{test_email}/"

    page.wait_for_url(f"{INTERNETNL_APP_URL}/mail/{test_email}/*/")

    score = page.locator('div.testresults-percentage')
    expect(score).to_have_attribute('data-resultscore', str(TEST_EMAIL_EXPECTED_SCORE))

@pytest.mark.xfail(raises=AssertionError, reason="test environment not complete enough to allow all tests to pass")
@pytest.mark.parametrize("probe", ALL_EMAIL_PROBES)
def test_your_email_probe_success(page, probe, test_email=TEST_EMAIL):
    page.goto(f"{INTERNETNL_APP_URL}/mail/{test_email}")
    page.wait_for_url(f"{INTERNETNL_APP_URL}/mail/{test_email}/*/")

    probe_result = page.locator(f'#mail{probe}-results')
    expect(probe_result).to_have_class('passed')

def test_your_connection_score(page):
    """Runs the 'Test your connection' and expects a decent result."""

    page.goto(INTERNETNL_APP_URL)

    page.locator('section.connectiontest button').click()

    assert page.url == f"{INTERNETNL_APP_URL}/connection/"

    page.wait_for_url(f"{INTERNETNL_APP_URL}/connection/*/results")

    score = page.locator('div.testresults-percentage')
    expect(score).to_have_attribute('data-resultscore', str(TEST_CONNECTION_EXPECTED_SCORE))

@pytest.mark.xfail(raises=AssertionError, reason="test environment not complete enough to allow all tests to pass")
@pytest.mark.parametrize("probe", ALL_CONNECTION_PROBES)
def test_your_connection_probe_success(page, probe):
    page.goto(f"{INTERNETNL_APP_URL}/connection/")
    page.wait_for_url(f"{INTERNETNL_APP_URL}/connection/*/results")

    probe_result = page.locator(f'#conn{probe}-results')
    expect(probe_result).to_have_class('passed')
