import os
import pytest
import subprocess
from selenium.webdriver.common.by import By
from selenium.common.exceptions import NoSuchElementException
from git import Repo
from git.exc import InvalidGitRepositoryError


DEFAULT_BROWSER_WIDTH = 1280
DEFAULT_BROWSER_HEIGHT = 1024


@pytest.fixture
def firefox_options(firefox_options):
    width = os.getenv('IT_BROWSER_WIDTH', DEFAULT_BROWSER_WIDTH)
    height = os.getenv('IT_BROWSER_HEIGHT', DEFAULT_BROWSER_HEIGHT)
    firefox_options.add_argument('--width={}'.format(width))
    firefox_options.add_argument('--height={}'.format(height))
    return firefox_options


def pytest_configure(config):
    pip_list_out, unused_err = subprocess.Popen(
        ['pip', 'list'], stdout=subprocess.PIPE).communicate()

    tags = 'Unknown'
    branch = 'Unknown'
    dependencies = 'Unknown'
    base_image = 'Unknown'
    try:
        # Assumes that the tests are being run from the tests/it subdirectory.
        r = Repo('/app')
        tags = r.git.describe(tags=True)
        branch = r.git.describe(all=True)
        dependencies = pip_list_out.decode('utf-8')
        base_image = os.environ.get('INTERNETNL_BASE_IMAGE', 'Unknown')
    except Exception:
        pass

    config._metadata['Internet.NL Git Describe Tags'] = tags
    config._metadata['Internet.NL Git Describe Branch'] = branch
    config._metadata['Internet.NL Pip List'] = dependencies
    config._metadata['Internet.NL Base Image'] = base_image
