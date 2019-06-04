import os
import pytest
import subprocess
from selenium.webdriver.common.by import By
from selenium.common.exceptions import NoSuchElementException
from git import Repo


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
    pip_list_out, unused_err = subprocess.Popen(['pip','list'], stdout=subprocess.PIPE).communicate()
    config._metadata['Internet.NL Version'] = Repo('/app').git.describe(tags=True)
    config._metadata['Internet.NL Dependencies'] = pip_list_out.decode('utf-8')
