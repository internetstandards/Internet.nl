"""Basis functionality that should always be present."""

import re
import requests
from playwright.sync_api import expect

FOOTER_TEXT = "Internet.nl is an initiative of the Internet community and the Dutch"

SECURITY_TXT_TEXT = "Policy: https://internet.nl/disclosure/"

ROBOTS_TXT_TEXT = "Disallow: /site/"


def test_index_http_ok(page, app_url):
    response = page.request.get(app_url)
    expect(response).to_be_ok()


def test_index_footer_text_present(page, app_url):
    page.goto(app_url)
    footer = page.locator("#footer")

    expect(footer).to_have_text(re.compile(FOOTER_TEXT))


def test_security_txt(page, app_url):
    page.goto(app_url + "/.well-known/security.txt")

    assert SECURITY_TXT_TEXT in page.content()


def test_robots_txt(page, app_url):
    page.goto(app_url + "/robots.txt")

    assert ROBOTS_TXT_TEXT in page.content()


def test_favicon_ico(page, app_url):
    response = page.request.get(app_url + "/favicon.ico")
    expect(response).to_be_ok()


def test_static_files(page, app_url):
    response = requests.get(app_url + "/static/logo_en.png")
    response.raise_for_status()


def test_generated_css_static_files(page, app_url):
    response = requests.get(app_url + "/static/css/style.css")
    response.raise_for_status()
    assert "@font-face" in response.text
    assert "expires" in response.headers


def test_generated_js_static_files(page, app_url):
    response = requests.get(app_url + "/static/js/menu-min.js")
    response.raise_for_status()
    assert "hideMenuButton" in response.text
    assert "expires" in response.headers


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
    assert response.headers["Strict-Transport-Security"] == "max-age=0"
    assert response.headers["location"] == f"http://conn.{app_domain}/"
