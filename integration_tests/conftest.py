# import logging
# import os
# import re
# import subprocess
# import time
# import urllib.request
# from datetime import timedelta
# import requests
# import pytest
# from pathlib import Path
# from bs4 import BeautifulSoup
# from dataclasses import dataclass
# from typing import Generator
# import dns.resolver
# import dns
#
#
# log = logging.getLogger(__name__)
#
# TIMEOUT = timedelta(seconds=int(os.environ.get("SYSTEM_TEST_TIMEOUT", 120)))
# BUILDPULL_TIMEOUT = timedelta(seconds=int(os.environ.get("SYSTEM_TEST_TIMEOUT", 300)))
#
# # which variables to inheret from shell environment
# ENVIRONMENT_INHERIT = ['PATH', 'DOCKER_HOST','HOME']
#
# PROJECT_ROOT = Path(__file__).parent.parent
# DOCKER_COMPOSE_FILE =  PROJECT_ROOT / "docker" / "docker-compose.yml"
# ENVIRONMENT_FILE = PROJECT_ROOT  / "test.env"
# WEB_SERVICE_NAME = "app"
# WEB_SERVICE_PORT = 8080
#
# RESOLVER_SERVICE_NAME = "unbound"
# RESOLVER_SERVICE_PORT = 53
#
# # on error, limit log output to these services as the rest (rabbitmq, postgres, etc) only provides noise
# LOG_OUTPUT_SERVICES = ["app", "worker"]
#
# INTERNETNL_USE_DOCKER_COMPOSE_PROJECT = os.environ.get("INTERNETNL_USE_DOCKER_COMPOSE_PROJECT", None)
# MANAGE_INSTANCE = INTERNETNL_USE_DOCKER_COMPOSE_PROJECT is None
#
# @dataclass
# class Response:
#     response: requests.Response
#     soup: BeautifulSoup
#
# class Internetnl:
#     url = None
#
#     def __init__(self, app_url, resolver_ip, resolver_port, docker_compose):
#         self.docker_compose = docker_compose
#         self.url = app_url
#
#         self.resolver = dns.resolver.Resolver()
#         self.resolver.nameservers = [resolver_ip]
#         self.resolver.port = resolver_port
#
#     def get(self, path) -> Response:
#         """Perform GET request on the instance."""
#
#         # response = requests.get(self.url + path, allow_redirects=False)
#         # response.raise_for_status()
#         text = self.docker_compose(f"exec browser curl --silent {self.url + path}")
#         response = requests.Response()
#         response.text = text
#         response.status_code = 200
#
#         return Response(response, BeautifulSoup(response.text, 'html.parser'))
#
#     def post(self, path, data=None) -> Response:
#         """Perform POST request on the instance."""
#
#         text = self.docker_compose(f"exec browser curl --silent {self.url + path} --data {data}")
#         response = requests.Response()
#         response.text = text
#         response.status_code = 200
#
#         return Response(response, BeautifulSoup(response.text, 'html.parser'))
#
#     def dns_resolve(self, domain, ipv6=False):
#         """Resolve domain using the Internet.nl unbound resolver."""
#
#         if ipv6:
#             return self.resolver.query(domain, dns.rdatatype.AAAA, tcp=True)
#         else:
#             return self.resolver.query(domain, dns.rdatatype.A, tcp=True)
#
#     def execute(self, command, service=WEB_SERVICE_NAME):
#         """Execute command in container."""
#
#         return self.docker_compose("exec {service} '{command}'")
#
# def internetnl_docker(docker_ip, pytestconfig, unique_id, request) -> Generator[Internetnl, None, None]:
#     """Returns running Internet.nl instance to test against."""
#
#     # generate temporary instance name or use provided one for existing environment
#     if MANAGE_INSTANCE:
#         project_name = "internetnl-test"
#     else:
#         project_name = INTERNETNL_USE_DOCKER_COMPOSE_PROJECT
#
#     def docker_compose(args, background=False, timeout=TIMEOUT, silent=False):
#         # requires Docker Compose V2, is implied by using the 'compose' command of the 'docker' executable
#         command = f'docker compose --ansi=never --env-file "{ENVIRONMENT_FILE}" --project-name "{project_name}" {args}'
#
#         log.info("Running command: %s", command)
#         env = {k:v for k,v in os.environ.items() if k in ENVIRONMENT_INHERIT}
#         if silent:
#             return subprocess.call(f"{command} &>/dev/null", shell=True, universal_newlines=True, timeout=timeout.seconds, env=env)
#         else:
#             return subprocess.check_output(command, shell=True, universal_newlines=True, timeout=timeout.seconds, env=env)
#
#     try:
#         if MANAGE_INSTANCE:
#             # prebuild and pull dependencies so up command doesn't timeout
#             docker_compose("build", timeout=BUILDPULL_TIMEOUT)
#             docker_compose("pull --ignore-pull-failures", timeout=BUILDPULL_TIMEOUT)
#
#             # bring all docker compose services up and wait for them to be healthy/running
#             docker_compose("up --wait")
#
#         # docker-compose binds port 8080 to an unique port number, extract that number here to form url
#         app_port = int(docker_compose(f'port {WEB_SERVICE_NAME} {WEB_SERVICE_PORT}').split(':')[-1])
#         app_url = f"http://{docker_ip}:{app_port:d}"
#
#         unbound_port = int(docker_compose(f'port {RESOLVER_SERVICE_NAME} {RESOLVER_SERVICE_PORT}').split(':')[-1])
#
#         # yield convenience instance to be used in testcases
#         internetnl = Internetnl(app_url, docker_ip, unbound_port, docker_compose)
#         time.sleep(10)
#         yield internetnl
#
#         # output logs for debug info in case the tests failed
#         for service in LOG_OUTPUT_SERVICES:
#             docker_compose(f"logs {service}")
#     except Exception as e:
#         pytest.fail(f"Error during setup of Docker Compose environment: {str(e)}", pytrace=False)
#
#     finally:
#         if MANAGE_INSTANCE:
#             # bring the test environment down and remove all containers and volumes
#             docker_compose("down -v", silent=True)
#
# @pytest.fixture(scope="session")
# def internetnl_live(request):
#     domainname = request.param
#     internetnl = Internetnl(f"https://{domainname}", "8.8.8.8", 53, None)
#     yield internetnl
#
# @pytest.fixture(scope="session")
# def docker_ip():
#     """Determine IP address for TCP connections to Docker containers."""
#
#     # When talking to the Docker daemon via a UNIX socket, route all TCP
#     # traffic to docker containers via the TCP loopback interface.
#     docker_host = os.environ.get("DOCKER_HOST", "").strip()
#     if not docker_host:
#         return "127.0.0.1"
#
#     match = re.match(r"^tcp://(.+?):\d+$", docker_host)
#     if not match:
#         raise ValueError(f'Invalid value for DOCKER_HOST: "{docker_host}".')
#     return match.group(1)
#
# @pytest.fixture(scope="session")
# def unique_id():
#     """Generate a unique (enough) ID so multiple test instances running at the same time don't conflict on resources (eg: Docker network/compose project name, etc)"""
#     return str(int(time.time()))
#
# # Allow testing against different internet.nl implementations/instances (eg: live https://internet.nl)
# INTERNETNL_IMPLEMENTATION = os.environ.get("INTERNETNL_IMPLEMENTATION", "docker-compose")
# if INTERNETNL_IMPLEMENTATION == "docker-compose":
#     internetnl: Internetnl = pytest.fixture(scope="session")(internetnl_docker)
# elif INTERNETNL_IMPLEMENTATION == "live":
#     internetnl: Internetnl = pytest.fixture(scope="session")(internetnl_live)
# else:
#     raise ValueError("Invalid INTERNETNL_IMPLEMENTATION value.")
#
# @pytest.fixture(scope="session")
# def browser(internetnl):
#     class Browser:
#         def visit(self, url, ipv6=False):
#             if ipv6:
#                 return internetnl.docker_compose(f"exec browser curl -vs6 {url}")
#             else:
#                 return internetnl.docker_compose(f"exec browser curl -vs {url}")
#
#     yield Browser()