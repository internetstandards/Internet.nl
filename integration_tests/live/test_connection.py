"""Basis functionality that should always be present."""
import pytest
import re
from playwright.sync_api import expect
from ..conftest import print_details_test_results
from ..conftest import ipv6_available

ALL_CONNECTION_PROBES_NO_IPV6 = {"resolver"}
ALL_CONNECTION_PROBES = {"ipv6", "resolver"}
TEST_CONNECTION_EXPECTED_SCORE_NO_IPV6 = 60.0
TEST_CONNECTION_EXPECTED_SCORE = 100.0


@pytest.mark.skipif(ipv6_available(), reason="IPv6 networking available")
def test_your_connection_score_no_ipv6(page, app_url):
    """Runs the 'Test your connection' and expects a decent result."""

    page.goto(app_url)

    page.locator("section.connectiontest button").click()

    page.wait_for_url(f"{app_url}/connection/*/results")

    score = page.locator("div.testresults-percentage")

    print_details_test_results(page)

    expect(score).to_have_attribute("data-resultscore", str(TEST_CONNECTION_EXPECTED_SCORE_NO_IPV6))


@pytest.mark.skipif(not ipv6_available(), reason="IPv6 networking not available")
def test_your_connection_score(page, app_url):
    """Runs the 'Test your connection' and expects a decent result."""

    page.goto(app_url)

    page.locator("section.connectiontest button").click()

    page.wait_for_url(f"{app_url}/connection/*/results")

    score = page.locator("div.testresults-percentage")

    print_details_test_results(page)

    expect(score).to_have_attribute("data-resultscore", str(TEST_CONNECTION_EXPECTED_SCORE))


@pytest.mark.parametrize("probe", ALL_CONNECTION_PROBES_NO_IPV6)
@pytest.mark.skipif(ipv6_available(), reason="IPv6 networking available")
def test_your_connection_probe_success_no_ipv6(page, app_url, probe):
    page.goto(f"{app_url}/connection/")
    page.wait_for_url(f"{app_url}/connection/*/results")

    probe_result = page.locator(f"#conn{probe}-results")
    expect(probe_result).to_have_class(re.compile(r"passed"))


@pytest.mark.parametrize("probe", ALL_CONNECTION_PROBES)
@pytest.mark.skipif(not ipv6_available(), reason="IPv6 networking not available")
def test_your_connection_probe_success_with_ipv6(page, app_url, probe):
    page.goto(f"{app_url}/connection/")
    page.wait_for_url(f"{app_url}/connection/*/results")

    probe_result = page.locator(f"#conn{probe}-results")
    expect(probe_result).to_have_class(re.compile(r"passed"))
