import pytest
import time
import subprocess
import sys

INTERNETNL_APP_URL = "http://internet.test"

TEST_DOMAIN = "target.test"

TEST_EMAIL = "target.test"


@pytest.fixture(scope="session")
def app_url():
    return INTERNETNL_APP_URL


@pytest.fixture(scope="session")
def test_domain(unique_id):
    return f"{unique_id}.{TEST_DOMAIN}"


@pytest.fixture(scope="session")
def test_email(unique_id):
    return TEST_EMAIL


@pytest.fixture(scope="session")
def unique_id():
    """Generate a unique (enough) ID so multiple test instances running at the same time don't conflict on
    resources (eg: Docker network/compose project name, etc)"""
    return str(int(time.time()))

@pytest.fixture(autouse=True)
def docker_logs():
    """This fixture is automatically added to each test. It will capture most relevant logs from Docker containers during the test run and print them so they may be presented on test failure."""

    # tail the container logs for application container and webserver, and output to stdout to have Pytest capture it
    command = (
        f'docker compose --ansi=never --env-file "test.env" --project-name "internetnl-test"'
        f" logs --follow --tail=0 app worker beat webserver"
    )
    process = subprocess.Popen(command, shell=True, universal_newlines=True, stdout=sys.stdout, stderr=sys.stdout)

    yield

    process.terminate()
