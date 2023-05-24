import pytest
import subprocess
import time
import os

APP_URLS = (os.environ.get("APP_URLS") or "https://internet.nl").split(",")

TEST_DOMAINS = (os.environ.get("TEST_DOMAINS") or "internet.nl").split(",")

TEST_EMAILS = os.environ.get("TEST_EMAIL", TEST_DOMAINS)

@pytest.fixture(scope="session", params=APP_URLS)
def app_url(request):
    return request.param

@pytest.fixture(scope="session", params=TEST_DOMAINS)
def test_domain(request):
    return request.param

@pytest.fixture(scope="session", params=TEST_EMAILS)
def test_email(request):
    return request.param
