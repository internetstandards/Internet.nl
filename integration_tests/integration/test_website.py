"""Basis functionality that should always be present."""

import re
import pytest
from playwright.sync_api import expect
from redis import Redis
from ..conftest import print_details_test_results
from ..conftest import print_results_url

INVALID_DOMAIN = "invalid-domain.example.com"

ALL_PROBES = {"ipv6", "dnssec", "tls", "appsecpriv", "rpki"}
TEST_DOMAIN_EXPECTED_SCORE = 100
# TODO: improve test environment to allow 100% score result
TEST_DOMAIN_EXPECTED_SCORE = 54


def test_reject_invalid_domain(page, app_url):
    domain = INVALID_DOMAIN

    page.goto(app_url)

    page.locator("#web-url").fill(domain)
    page.locator('form[action="/site/"] button').click()

    print_results_url(page)

    assert page.url == f"{app_url}/test-site/?invalid"


def test_your_website_score(page, app_url, test_domain):
    """Run "Test your website" from the frontpage and expect a decent result."""

    page.goto(app_url)

    page.locator("#web-url").fill(test_domain)
    page.locator('form[action="/site/"] button').click()

    assert page.url == f"{app_url}/site/{test_domain}/"

    page.wait_for_url(f"{app_url}/site/{test_domain}/*/")

    score = page.locator("meter#testresults-percentage")

    print_details_test_results(page)
    print_results_url(page)

    expect(score).to_have_attribute("value", str(TEST_DOMAIN_EXPECTED_SCORE))


def test_your_website_score_without_javascript(new_context, app_url, test_domain):
    """The website test should work without JavaScript, by following the link on the probe page."""

    page = new_context(java_script_enabled=False).new_page()
    page.goto(app_url)

    page.locator("#web-url").fill(test_domain)
    page.locator('form[action="/site/"] button').click()

    # the link points to the probe page itself until the results are ready, and if an earlier test
    # checked this domain, they are ready at once
    for _ in range(60):
        if re.search(rf"/site/{test_domain}/[0-9]+/$", page.url):
            break
        page.wait_for_timeout(2000)
        page.locator("main noscript a").click()

    print_results_url(page)

    expect(page.locator("meter#testresults-percentage")).to_have_attribute("value", str(TEST_DOMAIN_EXPECTED_SCORE))


@pytest.mark.skip(reason="test environment not complete enough to allow all tests to pass")
@pytest.mark.parametrize("probe", ALL_PROBES)
def test_your_website_probe_success(page, app_url, probe, test_domain):
    page.goto(f"{app_url}/site/{test_domain}/")
    page.wait_for_url(f"{app_url}/site/{test_domain}/*/")

    probe_result = page.locator(f"#site{probe}-results")
    expect(probe_result).to_have_class(re.compile(r"\bpassed\b"))


def test_ipv6_ns_with_bad_connectivity(page, app_url, unique_id):
    """Test if a target with a unresponsive IPv6 nameserver returns the correct result."""

    test_domain = f"{unique_id}.bad-ipv6-ns.test"

    page.goto(f"{app_url}/site/{test_domain}/")
    # make sure the test is completed
    page.wait_for_url(f"{app_url}/site/{test_domain}/*/")

    print_results_url(page)

    # verdicts are in closed details, so attached rather than visible
    # test results should indicate ipv6 ns are found
    expect(page.get_by_text("Two or more name servers of your domain have an IPv6 address.")).to_be_attached()

    # but some of them are not resolvable
    expect(page.get_by_text("Not all name servers that have an IPv6 address are reachable over IPv6.")).to_be_attached()


def test_rate_limit(page, app_url, test_domain):
    """Test if correct rate limit keys are created when starting a test."""

    test_domain = "www." + test_domain

    page.goto(app_url)

    page.locator("#web-url").fill(test_domain)
    page.locator('form[action="/site/"] button').click()
    page.wait_for_url(f"{app_url}/site/{test_domain}/", wait_until="commit")

    # the key only exists while the test runs, about a second here, too short for docker compose exec
    keys = Redis(host="redis").keys("dom:req_limit:*")
    assert keys, "there should be a redis entry for rate limiting"
    assert b"dom:req_limit:None" not in keys, "there should be no rate limit key created with `None` as IP address"
