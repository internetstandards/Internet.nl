"""Basis functionality that should always be present."""

import pytest
import re
from playwright.sync_api import expect

ALL_EMAIL_PROBES = {"ipv6", "dnssec", "tls", "auth", "rpki"}
TEST_EMAIL_EXPECTED_SCORE = 100

# maximum timeout is de default setting for maximum test duration + default timeout
MAX_TIMEOUT = 1000 * (200 + 30)


def test_your_email_score(page, app_url, test_email):
    """Runs the 'Test your email' and expects a decent result."""

    page.goto(app_url)

    page.locator("#mail-url").fill(test_email)
    page.locator("section.emailtest button").click()

    assert page.url == f"{app_url}/mail/{test_email}/"

    page.wait_for_url(f"{app_url}/mail/{test_email}/*/", timeout=MAX_TIMEOUT)

    score = page.locator("div.testresults-percentage")
    expect(score).to_have_attribute("data-resultscore", str(TEST_EMAIL_EXPECTED_SCORE))


@pytest.mark.parametrize("probe", ALL_EMAIL_PROBES)
def test_your_email_probe_success(page, app_url, test_email, probe):
    page.goto(f"{app_url}/mail/{test_email}")
    page.wait_for_url(f"{app_url}/mail/{test_email}/*/")

    probe_result = page.locator(f"#mail{probe}-results")
    expect(probe_result).to_have_class(re.compile(r"passed"))
