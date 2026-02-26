import pytest
import os
import time
import subprocess

APP_URLS = (os.environ.get("APP_URLS")).split(",")

TEST_DOMAINS = (os.environ.get("TEST_DOMAINS") or "internet.nl").split(",")

# use TEST_DOMAINS as default for TEST_EMAILS
TEST_EMAILS = (os.environ.get("TEST_EMAILS") or (os.environ.get("TEST_DOMAINS") or "internet.nl")).split(",")

BATCH_API_AUTH = os.environ.get("BATCH_API_AUTH")


IPV6_AVAILABILITY_DOMAIN = "internet.nl"


def ipv6_available():
    """Test if IPv6 is available inside development environment"""
    try:
        command = (
            "docker compose --ansi=never --project-name=internetnl-develop exec -ti app "
            + f"curl -6 --show-error --fail {IPV6_AVAILABILITY_DOMAIN}",
        )
        subprocess.check_output(command, shell=True)
    except subprocess.CalledProcessError:
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


@pytest.fixture(scope="session")
def test_domains_batch():
    return TEST_DOMAINS


@pytest.fixture(scope="session", params=APP_URLS)
def api_url(request):
    return f"{request.param}/api/batch/v2/"


@pytest.fixture(scope="session", params=TEST_EMAILS)
def test_email(request):
    return request.param


@pytest.fixture(scope="session")
def api_auth(request):
    if not BATCH_API_AUTH:
        pytest.skip("missing BATCH_API_AUTH credentials environment variable")
    return tuple(BATCH_API_AUTH.split(":"))


@pytest.fixture(scope="session")
def unique_id():
    """Generate a unique (enough) ID so multiple test instances running at the same time don't
    conflict on resources (eg: Docker network/compose project name, etc)"""
    return str(int(time.time()))


@pytest.fixture(autouse=True, scope="session")
def docker_compose_logs():
    """This fixture is automatically added to each test. It will capture most relevant logs from
    Docker containers during the test run and print them so they may be presented on test failure."""

    # tail the container logs for application container and webserver, and output to stdout to have Pytest capture it
    command = (
        "docker compose --ansi=never --project-name=internetnl-dev"
        " logs --follow --tail=0 app worker beat resolver webserver"
    )

    process = subprocess.Popen(command, shell=True, universal_newlines=True)

    yield process

    process.terminate()
