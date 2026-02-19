"""Basis functionality that should always be present."""

import pytest
from playwright.sync_api import expect
from ..conftest import print_details_test_results, print_red

from ..conftest import print_results_url
import requests
import re

ALL_CONNECTION_PROBES = {"ipv6", "resolver"}
TEST_CONNECTION_EXPECTED_SCORE = 100.0
# TODO: improve test environment to allow 100% score result
TEST_CONNECTION_EXPECTED_SCORE = 50.0


def test_your_connection_score(page, app_url, app_domain):
    """Runs the 'Test your connection' and expects a decent result."""

    # print failed requests
    page.on("requestfailed", lambda request: print_red("Request failed:", request.url, request.failure))

    page.goto(app_url)

    page.locator("section.connectiontest button").click()

    # expect to navigate to http url to start test, should be server over http
    page.wait_for_url(f"http://conn.{app_domain}/connection/")

    # wait for results, should be server over https
    page.wait_for_url(f"https://{app_domain}/connection/*/results")

    score = page.locator("div.testresults-percentage")

    print_details_test_results(page)
    print_results_url(page)
    print(
        "\nScreenshot, video and `trace.zip` can be found in `./test-results/`. "
        "Run using `make integration-test-trace` for trace.zip file. Upload trace file to: "
        "https://trace.playwright.dev for viewing."
    )

    expect(score).to_have_attribute("data-resultscore", str(TEST_CONNECTION_EXPECTED_SCORE))


@pytest.mark.skip(reason="test environment not complete enough to allow all tests to pass")
@pytest.mark.parametrize("probe", ALL_CONNECTION_PROBES)
def test_your_connection_probe_success(page, app_url, probe):
    page.goto(f"{app_url}/connection/")
    page.wait_for_url(f"{app_url}/connection/*/results")

    probe_result = page.locator(f"#conn{probe}-results")
    expect(probe_result).to_have_class("passed")


def test_connection_redirect(page, app_domain):
    """Connection test start should be redirected to  http conn. domain"""
    response = requests.get(f"https://en.{app_domain}/connection/", allow_redirects=False, verify=False)
    assert response.status_code == 301
    assert re.match(f"http://en.conn.{app_domain}/connection", response.headers["location"])


def test_direct_connect_browser_to_webserver(unique_id):
    """The browser should get the correct response if it connects directly to the IPv6 address."""

    response = requests.get(
        f"http://[fd00:43:1::100]/connection/addr-test/{unique_id}/?callback=jQuery123_123", allow_redirects=False
    )
    assert response.status_code == 200
    print(response.text)
    assert response.text.startswith("jQuery123")


@pytest.mark.parametrize(
    "subdomain",
    ["en", "nl"],
)
def test_conn_subdomain_redirects(subdomain, app_domain):
    """These subdomains should redirect to a domain without conn. in it and https."""
    url = f"http://{subdomain}.conn.{app_domain}/"
    redirect_url = f"https://{subdomain}.{app_domain}/"
    response = requests.get(url, allow_redirects=False)
    assert response.status_code == 301
    assert response.headers["location"] == redirect_url
