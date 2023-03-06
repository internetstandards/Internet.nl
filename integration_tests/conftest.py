import logging
import os
import re
import subprocess
import time
import urllib.request
from datetime import timedelta
import requests
import pytest
from pathlib import Path
from bs4 import BeautifulSoup
from dataclasses import dataclass
from typing import Generator

log = logging.getLogger(__name__)

TIMEOUT = timedelta(seconds=int(os.environ.get("SYSTEM_TEST_TIMEOUT", 60)))

PROJECT_ROOT = Path(__file__).parent.parent
DOCKER_COMPOSE_FILE =  PROJECT_ROOT / "docker" / "docker-compose.yml"
ENVIRONMENT_FILE = PROJECT_ROOT  / "test.env"
WEB_SERVICE_NAME = "app"
WEB_SERVICE_PORT = 8080

# on error, limit log output to these services as the rest (rabbitmq, postgres, etc) only provides noise
LOG_OUTPUT_SERVICES = ["app", "worker"]

INTERNETNL_USE_DOCKER_COMPOSE_PROJECT = os.environ.get("INTERNETNL_USE_DOCKER_COMPOSE_PROJECT", None)
MANAGE_INSTANCE = INTERNETNL_USE_DOCKER_COMPOSE_PROJECT is None

# generate temporary instance name or use provided one for existing environment
if MANAGE_INSTANCE:
    PROJECT_NAME = "internetnl_integration_test_{}".format(os.getpid())
else:
    PROJECT_NAME = INTERNETNL_USE_DOCKER_COMPOSE_PROJECT


@dataclass
class Response:
    response: requests.Response
    soup: BeautifulSoup

class Internetnl:
    url = None

    def __init__(self, url, docker_compose):
        self.url = url
        self.docker_compose = docker_compose

    def get(self, path) -> Response:
        """Perform GET request on the instance."""

        response = requests.get(self.url + path, allow_redirects=False)
        response.raise_for_status()

        return Response(response, BeautifulSoup(response.text, 'html.parser'))

    def post(self, path, data=None) -> Response:
        """Perform POST request on the instance."""

        response = requests.post(self.url + path, data=data, allow_redirects=False)
        response.raise_for_status()

        return Response(response, BeautifulSoup(response.text, 'html.parser'))

    def execute(self, command, service=WEB_SERVICE_NAME):
        """Execute command in container."""

        return self.docker_compose("exec {service} '{command}'")

def internetnl_docker(docker_ip, pytestconfig, request) -> Generator[Internetnl, None, None]:
    """Returns running Internet.nl instance to test against."""

    def docker_compose(args, background=False, timeout=TIMEOUT):
        # requires Docker Compose V2, is implied by using the 'compose' command of the 'docker' executable
        command = f'docker compose --ansi=never --file "{DOCKER_COMPOSE_FILE}" --env-file "{ENVIRONMENT_FILE}" --project-name "{PROJECT_NAME}" {args}'

        log.info("Running command: %s", command)

        if background:
            return subprocess.Popen(command, shell=True)
        else:
            return subprocess.check_output(command, shell=True, universal_newlines=True, timeout=timeout.seconds)

    if MANAGE_INSTANCE:
        # bring all docker compose services up and wait for them to be healthy/running
        docker_compose("up --wait")

    # docker-compose binds port 8080 to an unique port number, extract that number here to form url
    docker_port = int(docker_compose(f'port {WEB_SERVICE_NAME} {WEB_SERVICE_PORT}').split(':')[-1])
    url = f"http://{docker_ip}:{docker_port:d}"

    # yield convenience instance to be used in testcases
    internetnl = Internetnl(url, docker_compose)
    yield internetnl

    # output logs for debug info in case the tests failed
    for service in LOG_OUTPUT_SERVICES:
        docker_compose(f"logs {service}", background=True)

    if MANAGE_INSTANCE:
        # bring the test environment down and remove all containers and volumes
        docker_compose("down -v")

def internetnl_live():
    internetnl = Internetnl("https://internet.nl", None)
    yield internetnl

@pytest.fixture(scope="session")
def docker_ip():
    """Determine IP address for TCP connections to Docker containers."""

    # When talking to the Docker daemon via a UNIX socket, route all TCP
    # traffic to docker containers via the TCP loopback interface.
    docker_host = os.environ.get("DOCKER_HOST", "").strip()
    if not docker_host:
        return "127.0.0.1"

    match = re.match(r"^tcp://(.+?):\d+$", docker_host)
    if not match:
        raise ValueError(f'Invalid value for DOCKER_HOST: "{docker_host}".')
    return match.group(1)

@pytest.fixture()
def unique_id():
    return str(time.time()).replace(".","")

# Allow testing against different internet.nl implementations/instances (eg: live https://internet.nl)
INTERNETNL_IMPLEMENTATION = os.environ.get("INTERNETNL_IMPLEMENTATION", "docker-compose")
if INTERNETNL_IMPLEMENTATION == "docker-compose":
    internetnl: Internetnl = pytest.fixture(scope="session")(internetnl_docker)
elif INTERNETNL_IMPLEMENTATION == "live":
    internetnl: Internetnl = pytest.fixture(scope="session")(internetnl_live)
else:
    raise ValueError("Invalid INTERNETNL_IMPLEMENTATION value.")
