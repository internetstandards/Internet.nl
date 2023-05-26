"""Basis functionality that should always be present."""
import pytest
from playwright.sync_api import expect
from ..conftest import print_details_test_results

ALL_EMAIL_PROBES = {"ipv6", "dnssec", "tls", "auth", "rpki"}
TEST_EMAIL_EXPECTED_SCORE = 100
# TODO: improve test environment to allow 100% score result
TEST_EMAIL_EXPECTED_SCORE = 17


def test_your_email_score(page, app_url, test_email):
    """Runs the 'Test your email' and expects a decent result."""

    page.goto(app_url)

    page.locator("#mail-url").fill(test_email)
    page.locator("section.emailtest button").click()

    assert page.url == f"{app_url}/mail/{test_email}/"

    page.wait_for_url(f"{app_url}/mail/{test_email}/*/")

    score = page.locator("div.testresults-percentage")

    print_details_test_results(page)

    expect(score).to_have_attribute("data-resultscore", str(TEST_EMAIL_EXPECTED_SCORE))


@pytest.mark.skip(reason="test environment not complete enough to allow all tests to pass")
@pytest.mark.parametrize("probe", ALL_EMAIL_PROBES)
def test_your_email_probe_success(page, app_url, probe, test_email):
    page.goto(f"{app_url}/mail/{test_email}")
    page.wait_for_url(f"{app_url}/mail/{test_email}/*/")

    probe_result = page.locator(f"#mail{probe}-results")
    expect(probe_result).to_have_class("passed")
