import subprocess
import pytest
from packaging.version import Version


def pytest_sessionstart():
    """Some versions of Docker/Compose are incompatible because of the way their networking/DNS
    works. Check this and instruct the user how to resolve the issues."""

    docker_server_version = subprocess.check_output(
        "docker version --format '{{.Server.Version}}'",
        shell=True,
        universal_newlines=True,
    ).strip()

    if Version("25.0.5") <= Version(docker_server_version) < Version("26.1.3"):
        pytest.fail(
            f"Docker Server version {docker_server_version} not compatible, refer to "
            "`documentation/Docker-getting-started.md#Prerequisites` for more info."
        )
