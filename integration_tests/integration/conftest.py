import pytest
import subprocess
import time

INTERNETNL_APP_URL = "http://internet.test"

@pytest.fixture(scope="session")
def app_url():
    return INTERNETNL_APP_URL

@pytest.fixture(scope="session")
def unique_id():
    """Generate a unique (enough) ID so multiple test instances running at the same time don't conflict on resources (eg: Docker network/compose project name, etc)"""
    return str(int(time.time()))
