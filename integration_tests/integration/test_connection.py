"""Basis functionality that should always be present."""
from datetime import timedelta
import pytest
import re
from playwright.sync_api import Page, expect
from pytest_playwright import pytest_playwright
from ..conftest import print_details_test_results

ALL_CONNECTION_PROBES = {"ipv6", "resolver"}
TEST_CONNECTION_EXPECTED_SCORE = 100.0
# TODO: improve test environment to allow 100% score result
TEST_CONNECTION_EXPECTED_SCORE = 50.0

def test_your_connection_score(page, app_url):
    """Runs the 'Test your connection' and expects a decent result."""

    page.goto(app_url)

    page.locator('section.connectiontest button').click()

    assert page.url == f"{app_url}/connection/"

    page.wait_for_url(f"{app_url}/connection/*/results")

    score = page.locator('div.testresults-percentage')

    print_details_test_results(page)

    expect(score).to_have_attribute('data-resultscore', str(TEST_CONNECTION_EXPECTED_SCORE))

@pytest.mark.skip(reason="test environment not complete enough to allow all tests to pass")
@pytest.mark.parametrize("probe", ALL_CONNECTION_PROBES)
def test_your_connection_probe_success(page, app_url, probe):
    page.goto(f"{app_url}/connection/")
    page.wait_for_url(f"{app_url}/connection/*/results")

    probe_result = page.locator(f'#conn{probe}-results')
    expect(probe_result).to_have_class('passed')
