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
    """Branding is disabled on develop, so no footer text, only version"""
    page.goto(app_url)
    footer = page.locator("#footer")

    expect(footer).not_to_have_text(re.compile(FOOTER_TEXT))


def test_robots_txt(page, app_url):
    page.goto(app_url + "/robots.txt")

    assert ROBOTS_TXT_TEXT in page.content()


def test_favicon_ico(page, app_url):
    response = page.request.get(app_url + "/favicon.ico")
    expect(response).to_be_ok()


def test_static_files(page, app_url):
    response = requests.get(app_url + "/static/logo_en.png", verify=False)
    response.raise_for_status()


def test_generated_css_static_files(page, app_url):
    response = requests.get(app_url + "/static/css/style.css", verify=False)
    response.raise_for_status()
    assert "@font-face" in response.text
    assert "expires" in response.headers


def test_generated_js_static_files(page, app_url):
    response = requests.get(app_url + "/static/js/menu-min.js", verify=False)
    response.raise_for_status()
    assert "hideMenuButton" in response.text
    assert "expires" in response.headers
