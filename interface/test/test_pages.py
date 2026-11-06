import re

import pytest
from django.core.cache import cache
from django.core.management import call_command

from checks.models import ConnectionTest, DomainTestReport

PAGES = [
    "/",
    "/about/",
    "/contact/",
    "/faqs/",
    "/faqs/report/",
    "/faqs/badges/",
    "/widget-site/",
    "/widget-mail/",
    "/halloffame/",
    "/articles/",
    "/test-site/",
    "/test-mail/",
    "/test-connection/",
    "/disclosure/",
    "/privacy/",
    "/copyright/",
    "/accessibility/",
    "/connection/",
    "/statistics/20260101/20260131/",
    "/no-such-page/",
]

# content that only belongs on internet.nl itself, not on other deployments
INTERNETNL_CONTENT = ["question@internet.nl", "logos/logo", "images/ncsc"]


@pytest.mark.parametrize("branding", [True, False])
@pytest.mark.parametrize("path", PAGES)
def test_page(db, client, settings, path, branding):
    settings.INTERNETNL_BRANDING = branding
    # cached pages do not vary on branding, which is fixed per deployment
    cache.delete_pattern("cached_page:*")
    response = client.get(path)
    assert response.status_code == (404 if path == "/no-such-page/" else 200)
    html = response.content.decode()
    assert "css/style-min.css?v=" in html, "static file URLs should carry the release"
    if branding:
        assert "logos/logo" in html
    else:
        assert not [text for text in INTERNETNL_CONTENT if text in html]
        # the test settings have no custom.po, so no news
        assert 'href="/article/' not in html


@pytest.mark.parametrize(
    "path, target",
    [
        ("/halloffame/web/", "/halloffame/"),
        ("/halloffame/mail/", "/halloffame/"),
        ("/blogs/", "/articles/"),
        ("/blogs/someone/an-article/", "/article/an-article"),
        ("/news/", "/articles/"),
        ("/news/an-article/", "/article/an-article"),
    ],
)
def test_redirect(client, path, target):
    assert client.get(path).url == target


def test_example_reports(db, client):
    """The example reports are from before some of the current subtests, like many permalinks."""
    call_command("loaddata", "example_reports")
    pages = [f"/site/{report.domain}/{report.id}/" for report in DomainTestReport.objects.all()]
    pages += [f"/connection/{test.test_id}/results" for test in ConnectionTest.objects.all()]
    for page in pages:
        response = client.get(page)
        assert response.status_code == 200
        ids = re.findall(r'<details class="accordion" id="([^"]+)"', response.content.decode())
        assert ids and len(ids) == len(set(ids)), f"subtest ids on {page} should be unique"
