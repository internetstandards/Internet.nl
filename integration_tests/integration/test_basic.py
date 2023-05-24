"""Basis functionality that should always be present."""
from datetime import timedelta
import pytest
import re
from playwright.sync_api import Page, expect
from pytest_playwright import pytest_playwright
from ..conftest import print_details_test_results

FOOTER_TEXT = "Internet.nl is an initiative of the Internet community and the Dutch"

SECURITY_TXT_TEXT = "Contact: https://internet.nl/disclosure/"

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

