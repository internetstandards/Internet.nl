import os
import subprocess

import pytest
from git import Repo

DEFAULT_BROWSER_WIDTH = 1280
DEFAULT_BROWSER_HEIGHT = 1024


# Configure the pytest-selenium plugin to configure the Firefox browser(s) in
# which tests will be executed.
@pytest.fixture
def firefox_options(firefox_options):
    width = os.getenv("IT_BROWSER_WIDTH", DEFAULT_BROWSER_WIDTH)
    height = os.getenv("IT_BROWSER_HEIGHT", DEFAULT_BROWSER_HEIGHT)
    firefox_options.add_argument("--width={}".format(width))
    firefox_options.add_argument("--height={}".format(height))
    return firefox_options


# Using the pytest-metadata plugin. add information about the test setup to the
# 'Environment' section of the pytest-html plugin produced HTML report. Both
# plugins are imported and enabled automatically by the pytest-selenium plugin.
#
# See: https://github.com/pytest-dev/pytest-html#environment
# See: https://github.com/pytest-dev/pytest-metadata
# See: https://docs.pytest.org/en/latest/_modules/_pytest/hookspec.html
def pytest_configure(config):
    if not hasattr(config, "_metadata") or not config._metadata:
        return

    pip_list_out, unused_err = subprocess.Popen(["pip", "list"], stdout=subprocess.PIPE).communicate()

    tags = "Unknown"
    branch = "Unknown"
    dependencies = "Unknown"
    base_image = "Unknown"
    test_filter = "Unknown"
    try:
        # Assumes that the tests are being run from the tests/it subdirectory.
        r = Repo("/app")
        tags = r.git.describe(tags=True)
        branch = r.git.describe(all=True)
        dependencies = pip_list_out.decode("utf-8")
        base_image = os.environ.get("INTERNETNL_BASE_IMAGE", "Unknown")
        test_filter = config.getoption("-k", "Unknown")
    except Exception:
        pass

    config._metadata["Internet.NL Git Describe Tags"] = tags
    config._metadata["Internet.NL Git Describe Branch"] = branch
    config._metadata["Internet.NL Pip List"] = dependencies
    config._metadata["Internet.NL Base Image"] = base_image
    config._metadata["Internet.NL Test Filter"] = test_filter
