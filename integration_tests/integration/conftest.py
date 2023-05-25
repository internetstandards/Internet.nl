import pytest
import subprocess
import time

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
    """Generate a unique (enough) ID so multiple test instances running at the same time don't conflict on resources (eg: Docker network/compose project name, etc)"""
    return str(int(time.time()))
