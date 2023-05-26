import pytest
import os
import socket

APP_URLS = (os.environ.get("APP_URLS") or "https://internet.nl").split(",")

TEST_DOMAINS = (os.environ.get("TEST_DOMAINS") or "internet.nl").split(",")

TEST_EMAILS = os.environ.get("TEST_EMAIL", TEST_DOMAINS)


def ipv6_available():
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, 0)
    try:
        s.connect(("internet.nl", 80, 0, 0))
    except (socket.gaierror, OSError):
        return False
    return True


def pytest_report_header(config):
    return [
        f"app_urls: {','.join(APP_URLS)}",
        f"test_domains: {','.join(TEST_DOMAINS)}",
        f"test_emails: {','.join(TEST_EMAILS)}",
        f"ipv6_available: {ipv6_available()}",
    ]


@pytest.fixture(scope="session", params=APP_URLS)
def app_url(request):
    return request.param


@pytest.fixture(scope="session", params=TEST_DOMAINS)
def test_domain(request):
    return request.param


@pytest.fixture(scope="session", params=TEST_EMAILS)
def test_email(request):
    return request.param
