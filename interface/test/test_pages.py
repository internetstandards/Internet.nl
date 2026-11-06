import pytest
from django.core.cache import cache

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
    assert response.status_code == 200
    html = response.content.decode()
    assert "css/style-min.css?v=" in html, "static file URLs should carry the release"
    if branding:
        assert "logos/logo" in html
    else:
        assert not [text for text in INTERNETNL_CONTENT if text in html]
        # the test settings have no custom.po, so no news
        assert 'href="/article/' not in html
