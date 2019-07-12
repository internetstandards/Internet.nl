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


# See: https://docs.pytest.org/en/latest/_modules/_pytest/hookspec.html
def pytest_configure(config):
    """
    Allows plugins and conftest files to perform initial configuration.

    This hook is called for every plugin and initial conftest file
    after command line options have been parsed.

    After that, the hook is called for other conftest files as they are
    imported.

    .. note::
        This hook is incompatible with ``hookwrapper=True``.

    :arg _pytest.config.Config config: pytest config object
    """
    pip_list_out, unused_err = subprocess.Popen(
        ['pip', 'list'], stdout=subprocess.PIPE).communicate()

    tags = 'Unknown'
    branch = 'Unknown'
    dependencies = 'Unknown'
    base_image = 'Unknown'
    test_filter = 'Unknown'
    try:
        # Assumes that the tests are being run from the tests/it subdirectory.
        r = Repo('/app')
        tags = r.git.describe(tags=True)
        branch = r.git.describe(all=True)
        dependencies = pip_list_out.decode('utf-8')
        base_image = os.environ.get('INTERNETNL_BASE_IMAGE', 'Unknown')
        test_filter = config.getoption('-k', 'Unknown')
    except Exception:
        pass

    config._metadata['Internet.NL Git Describe Tags'] = tags
    config._metadata['Internet.NL Git Describe Branch'] = branch
    config._metadata['Internet.NL Pip List'] = dependencies
    config._metadata['Internet.NL Base Image'] = base_image
    config._metadata['Internet.NL Test Filter'] = test_filter
