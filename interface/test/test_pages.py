import re
import subprocess
import sys
from pathlib import Path

import polib
import pytest
from django.core.cache import cache
from django.core.management import call_command
from django.utils import translation

from checks.models import ConnectionTest, DomainTestReport
from interface.views import FAQ_CATEGORIES, article_index
from internetnl.settings_utils import BASE_DIR

PAGES = [
    "/",
    "/about/",
    "/contact/",
    "/faqs/",
    "/widget-site/",
    "/widget-mail/",
    "/halloffame/",
    "/articles/",
    "/disclosure/",
    "/privacy/",
    "/copyright/",
    "/accessibility/",
    "/connection/",
    "/statistics/20260101/20260131/",
    "/no-such-page/",
]
# the knowledge base links to the test pages and its articles
PAGES += [url for _category, links in FAQ_CATEGORIES for url, _title in links]

# images that only internet.nl shows; the texts are for other deployments to translate themselves
INTERNETNL_IMAGES = ["logos/logo", "images/ncsc"]


@pytest.fixture(scope="module")
def locale_path(tmp_path_factory):
    """The translations, built as the image builds them."""
    path = tmp_path_factory.mktemp("translations")
    (path / "translations").symlink_to(Path(BASE_DIR) / "translations")
    subprocess.run([sys.executable, Path(BASE_DIR) / "bin/pofiles.py", "to_django"], cwd=path, check=True)
    for po in path.glob("locale/*/LC_MESSAGES/django.po"):
        polib.pofile(po).save_as_mofile(po.with_suffix(".mo"))
    return path / "locale"


@pytest.fixture(autouse=True)
def translations(settings, locale_path):
    settings.LOCALE_PATHS = [str(locale_path)]


@pytest.fixture(scope="module")
def raw_keys(locale_path):
    """Find the translation keys that show as text, as they do when a translation is missing."""
    # from the first two words of a key, so that link texts such as "test reports" do not count;
    # both languages, because some articles are only in Dutch
    msgids = {entry.msgid for po in locale_path.glob("*/LC_MESSAGES/django.po") for entry in polib.pofile(po)}
    prefixes = "|".join({re.escape(" ".join(msgid.split()[:2])) for msgid in msgids if " " in msgid})
    pattern = re.compile(
        rf'(?:>|(?:alt|aria-label|content|placeholder|title)=")\s*((?:{prefixes})(?: \.?[A-Za-z0-9_-]+)*)\s*[<"]'
    )
    # other deployments translate the custom keys in a custom.po, which the tests do not have
    return lambda html: [key for key in pattern.findall(html) if "custom" not in key.split()]


def get(client, path, language):
    response = client.get(path, headers={"accept-language": language})
    return response, response.content.decode()


@pytest.mark.parametrize("language", ["nl", "en"])
@pytest.mark.parametrize("branding", [True, False])
@pytest.mark.parametrize("path", PAGES)
def test_page(db, client, settings, raw_keys, path, branding, language):
    settings.INTERNETNL_BRANDING = branding
    # cached pages do not vary on branding, which is fixed per deployment
    cache.delete_pattern("cached_page:*")
    response, html = get(client, path, language)
    assert response.status_code == (404 if path == "/no-such-page/" else 200)
    keys = raw_keys(html)
    assert not keys
    assert "css/style-min.css?v=" in html, "static file URLs should carry the release"
    if branding:
        assert "logos/logo" in html
    else:
        assert not [image for image in INTERNETNL_IMAGES if image in html]
        # the test settings have no custom.po, so no news
        assert "news-card" not in html


@pytest.mark.parametrize("language", ["nl", "en"])
def test_articles(db, client, settings, raw_keys, language):
    settings.INTERNETNL_BRANDING = True
    with translation.override(language):
        articles = article_index()
    assert articles
    for article in articles:
        response, html = get(client, f"/article/{article}/", language)
        assert response.status_code == 200, article
        keys = raw_keys(html)
        assert not keys, article


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


def test_example_reports(db, client, monkeypatch, raw_keys):
    """Old reports, like many shared permalinks, lack some of the current subtests."""
    # finding the www and non-www variants to link to takes DNS lookups, which time out here
    monkeypatch.setattr("interface.views.domain.get_direct_domains", lambda address: ([], []))
    call_command("loaddata", "example_reports")
    pages = [f"/site/{report.domain}/{report.id}/" for report in DomainTestReport.objects.all()]
    pages += [f"/connection/{test.test_id}/results" for test in ConnectionTest.objects.all()]
    for page in pages:
        response, html = get(client, page, "en")
        assert response.status_code == 200
        keys = raw_keys(html)
        assert not keys, page
        ids = re.findall(r'<details class="accordion" id="([^"]+)"', html)
        assert ids and len(ids) == len(set(ids)), f"subtest ids on {page} should be unique"
