"""Basis functionality that should always be present."""
import re
import pytest
import requests
from playwright.sync_api import expect

FOOTER_TEXT_EN = "Internet.nl is an initiative of the Internet community and the Dutch"
FOOTER_TEXT_NL = "Internet.nl is een initiatief van de internetgemeenschap en de Nederlandse"

SECURITY_TXT_TEXT = "Policy: https://internet.nl/disclosure/"

ROBOTS_TXT_TEXT = "Disallow: /site/"


def test_index_http_ok(page, app_url_subdomain):
    response = page.request.get(app_url_subdomain)
    expect(response).to_be_ok()


@pytest.mark.parametrize(
    ("app_url", "footer_text"),
    [("https://en.internet.test", FOOTER_TEXT_EN), ("https://nl.internet.test", FOOTER_TEXT_NL)],
)
def test_index_footer_text_present(page, app_url, footer_text):
    page.goto(app_url)
    footer = page.locator("#footer")

    expect(footer).to_have_text(re.compile(footer_text))


def test_security_txt(page, app_url_subdomain):
    page.goto(app_url_subdomain + "/.well-known/security.txt")

    assert SECURITY_TXT_TEXT in page.content()


def test_robots_txt(page, app_url_subdomain):
    page.goto(app_url_subdomain + "/robots.txt")

    assert ROBOTS_TXT_TEXT in page.content()


def test_favicon_ico(page, app_url_subdomain):
    response = page.request.get(app_url_subdomain + "/favicon.ico")
    expect(response).to_be_ok()


def test_static_files(page, app_url_subdomain):
    response = requests.get(app_url_subdomain + "/static/logo_en.png", verify=False)
    response.raise_for_status()


def test_generated_css_static_files(page, app_url_subdomain):
    response = requests.get(app_url_subdomain + "/static/css/style-min.css", verify=False)
    response.raise_for_status()
    assert "@font-face" in response.text
    assert "expires" in response.headers


def test_generated_js_static_files(page, app_url_subdomain):
    response = requests.get(app_url_subdomain + "/static/js/menu-min.js", verify=False)
    response.raise_for_status()
    assert "hideMenuButton" in response.text
    assert "expires" in response.headers


@pytest.mark.parametrize(
    "path",
    ["/grafana", "/prometheus", "/prometheus/targets"],
)
def test_monitoring_auth(page, app_url, path):
    """Monitoring endpoints must be behind basic auth."""

    response = requests.get(app_url + path, verify=False)
    assert response.status_code == 401

    # MONITORING_AUTH provided in docker/test.env
    auth = ("test", "test")

    response = requests.get(app_url + path, auth=auth, verify=False)
    response.raise_for_status()


def test_monitoring_auth_raw(page, app_url):
    """Monitoring endpoints must be behind basic auth."""
    path = "/grafana"

    response = requests.get(app_url + path, verify=False)
    assert response.status_code == 401

    # MONITORING_AUTH_RAW provided in docker/test.env
    auth = ("test_raw", "test_raw")

    response = requests.get(app_url + path, auth=auth, verify=False)
    response.raise_for_status()


def test_no_server_banner(page, app_url_subdomain):
    response = requests.get(app_url_subdomain, verify=False)
    assert response.headers["server"] == "nginx"


def test_http_redirect_https(page, app_url_subdomain):
    response = requests.get(app_url_subdomain.replace("https", "http"), allow_redirects=False)
    assert response.status_code == 301
    assert re.match(app_url_subdomain, response.headers["location"])


def test_nowww_class_b(page, app_domain, app_url):
    response = requests.get(f"https://www.{app_domain}", allow_redirects=False, verify=False)
    assert response.status_code == 301
    assert response.headers["location"] == f"{app_url}/"


def test_default_sni_none(app_domain):
    """Default vhost should 404 on any non explicitly configured domain. #894"""

    not_configured_domain = "telefax.test"

    # make a https request to the webserver's adres but request a vhost that is not configured
    response = requests.get(
        f"https://{app_domain}", headers={"Host": not_configured_domain}, verify=False, allow_redirects=False
    )
    assert response.status_code == 404


def test_conn_over_https_no_hsts(app_domain):
    """Serving conn. over HTTPS should disable HSTS and downgrade to HTTP. #894"""

    # make a https request to the webserver's adres but request a vhost that is not configured
    response = requests.get(f"https://conn.{app_domain}", verify=False, allow_redirects=False)
    assert response.status_code == 301
    assert response.headers["Strict-Transport-Security"] == "max-age=0;"
    assert response.headers["location"] == f"http://conn.{app_domain}"
