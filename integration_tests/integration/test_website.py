"""Basis functionality that should always be present."""
import pytest
from playwright.sync_api import expect
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
    page.locator("section.websitetest button").click()

    print_results_url(page)

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
    print_results_url(page)

    expect(score).to_have_attribute("data-resultscore", str(TEST_DOMAIN_EXPECTED_SCORE))


@pytest.mark.skip(reason="test environment not complete enough to allow all tests to pass")
@pytest.mark.parametrize("probe", ALL_PROBES)
def test_your_website_probe_success(page, app_url, probe, test_domain):
    page.goto(f"{app_url}/site/{test_domain}/")
    page.wait_for_url(f"{app_url}/site/{test_domain}/*/")

    probe_result = page.locator(f"#site{probe}-results")
    expect(probe_result).to_have_class("passed")


def test_ipv6_ns_with_bad_connectivity(page, app_url, unique_id):
    """Test if a target with a unresponsive IPv6 nameserver returns the correct result."""

    test_domain = f"{unique_id}.bad-ipv6-ns.test"

    page.goto(f"{app_url}/site/{test_domain}/")
    # make sure the test has been started
    page.get_by_text(f"Website test: {test_domain}")
    # make sure the test is completed
    page.wait_for_url(f"{app_url}/site/{test_domain}/*/")

    print_results_url(page)

    # test results should indicate ipv6 ns are found
    expect(page.get_by_text("Two or more name servers of your domain have an IPv6 address."))

    # but some of them are not resolvable
    expect(page.get_by_text("Not all name servers that have an IPv6 address are reachable over IPv6."))


def test_rate_limit(page, app_url, test_domain, docker_compose_exec):
    """Test if correct rate limit keys are created when starting a test."""

    test_domain = "www." + test_domain

    page.goto(app_url)

    page.locator("#web-url").fill(test_domain)
    page.locator("section.websitetest button").click()

    rate_limit_redis_entry = docker_compose_exec("redis", "redis-cli keys dom:req_limit:*").decode("utf8").strip()
    assert rate_limit_redis_entry, "there should be a redis entry for rate limiting"
    assert not rate_limit_redis_entry.endswith(
        "None"
    ), "there should be no rate limit key created with `None` as IP address"
