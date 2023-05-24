"""Basis functionality that should always be present."""
from datetime import timedelta
import pytest
import os
import re
from playwright.sync_api import Page, expect
from pytest_playwright import pytest_playwright
from ..utils import print_details_test_results
from .utils import ipv6_available

INVALID_DOMAIN = "invalid-domain.example.com"

ALL_PROBES = {"ipv6", "dnssec", "tls", "appsecpriv", "rpki"}
TEST_DOMAIN_EXPECTED_SCORE = 100

ALL_EMAIL_PROBES = {"ipv6", "dnssec", "tls", "auth", "rpki"}
TEST_EMAIL_EXPECTED_SCORE = 100

ALL_CONNECTION_PROBES_NO_IPV6 = {"resolver"}
ALL_CONNECTION_PROBES = {"ipv6", "resolver"}
TEST_CONNECTION_EXPECTED_SCORE_NO_IPV6 = 60.0
TEST_CONNECTION_EXPECTED_SCORE = 100.0

FOOTER_TEXT = "Internet.nl is an initiative of the Internet community and the Dutch"

SECURITY_TXT_TEXT = "Contact: https://internet.nl/disclosure/"

ROBOTS_TXT_TEXT = "Disallow: /site/"

def test_index_http_ok(page, app_url):
    response = page.request.get(app_url)
    expect(response).to_be_ok()

def test_index_footer_text_present(page, app_url):
    page.goto(app_url)
    footer = page.locator("#footer")

    expect(footer).to_have_text(re.compile(FOOTER_TEXT))

def test_security_txt(page, app_url):
    page.goto(app_url + "/.well-known/security.txt")

    assert SECURITY_TXT_TEXT in page.content()

def test_robots_txt(page, app_url):
    page.goto(app_url + "/robots.txt")

    assert ROBOTS_TXT_TEXT in page.content()

def test_favicon_ico(page, app_url):
    response = page.request.get(app_url + "/favicon.ico")
    expect(response).to_be_ok()

def test_reject_invalid_domain(page, app_url):
    domain = INVALID_DOMAIN

    page.goto(app_url)

    page.locator('#web-url').fill(domain)
    page.locator('section.websitetest button').click()

    assert page.url == f"{app_url}/test-site/?invalid"

def test_your_website_score(page, app_url, test_domain):
    """Run "Test your website" from the frontpage and expect a decent result."""

    page.goto(app_url)

    page.locator('#web-url').fill(test_domain)
    page.locator('section.websitetest button').click()

    assert page.url == f"{app_url}/site/{test_domain}/"

    page.wait_for_url(f"{app_url}/site/{test_domain}/*/")

    score = page.locator('div.testresults-percentage')
    expect(score).to_have_attribute('data-resultscore', str(TEST_DOMAIN_EXPECTED_SCORE))

@pytest.mark.parametrize("probe", ALL_PROBES)
def test_your_website_probe_success(page, app_url, test_domain, probe):

    page.goto(f"{app_url}/site/{test_domain}/")
    page.wait_for_url(f"{app_url}/site/{test_domain}/*/")

    probe_result = page.locator(f'#site{probe}-results')
    expect(probe_result).to_have_class(re.compile(r'passed'))


def test_your_email_score(page, app_url, test_email):
    """Runs the 'Test your email' and expects a decent result."""

    page.goto(app_url)

    page.locator('#mail-url').fill(test_email)
    page.locator('section.emailtest button').click()

    assert page.url == f"{app_url}/mail/{test_email}/"

    page.wait_for_url(f"{app_url}/mail/{test_email}/*/")

    score = page.locator('div.testresults-percentage')
    expect(score).to_have_attribute('data-resultscore', str(TEST_EMAIL_EXPECTED_SCORE))

@pytest.mark.parametrize("probe", ALL_EMAIL_PROBES)
def test_your_email_probe_success(page, app_url, test_email, probe):
    page.goto(f"{app_url}/mail/{test_email}")
    page.wait_for_url(f"{app_url}/mail/{test_email}/*/")

    probe_result = page.locator(f'#mail{probe}-results')
    expect(probe_result).to_have_class(re.compile(r'passed'))

@pytest.mark.skipif(ipv6_available(), reason="IPv6 networking available")
def test_your_connection_score_no_ipv6(page, app_url):
    """Runs the 'Test your connection' and expects a decent result."""

    page.goto(app_url)

    page.locator('section.connectiontest button').click()

    page.wait_for_url(f"{app_url}/connection/*/results")

    score = page.locator('div.testresults-percentage')

    print_details_test_results(page)

    expect(score).to_have_attribute('data-resultscore', str(TEST_CONNECTION_EXPECTED_SCORE_NO_IPV6))

@pytest.mark.skipif(not ipv6_available(), reason="IPv6 networking not available")
def test_your_connection_score(page, app_url):
    """Runs the 'Test your connection' and expects a decent result."""

    page.goto(app_url)

    page.locator('section.connectiontest button').click()

    page.wait_for_url(f"{app_url}/connection/*/results")

    score = page.locator('div.testresults-percentage')

    print_details_test_results(page)

    expect(score).to_have_attribute('data-resultscore', str(TEST_CONNECTION_EXPECTED_SCORE))

@pytest.mark.parametrize("probe", ALL_CONNECTION_PROBES_NO_IPV6)
@pytest.mark.skipif(ipv6_available(), reason="IPv6 networking available")
def test_your_connection_probe_success_no_ipv6(page, app_url, probe):
    page.goto(f"{app_url}/connection/")
    page.wait_for_url(f"{app_url}/connection/*/results")

    probe_result = page.locator(f'#conn{probe}-results')
    expect(probe_result).to_have_class(re.compile(r'passed'))

@pytest.mark.parametrize("probe", ALL_CONNECTION_PROBES)
@pytest.mark.skipif(not ipv6_available(), reason="IPv6 networking not available")
def test_your_connection_probe_success(page, app_url, probe):
    page.goto(f"{app_url}/connection/")
    page.wait_for_url(f"{app_url}/connection/*/results")

    probe_result = page.locator(f'#conn{probe}-results')
    expect(probe_result).to_have_class(re.compile(r'passed'))

