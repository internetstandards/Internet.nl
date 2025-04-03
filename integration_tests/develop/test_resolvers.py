"""Test internal resolvers."""

import pytest
import subprocess
from ..conftest import ipv6_available


def docker_compose_exec(service, command, env="develop"):
    cmd = f"docker compose --ansi=never --project-name=internetnl-{env} exec -ti {service} /bin/sh -c '{command}'"
    print(cmd)
    try:
        output = subprocess.check_output(cmd, shell=True, universal_newlines=True, stderr=subprocess.STDOUT)
        returncode = 0
    except subprocess.CalledProcessError as e:
        print(dir(e))
        returncode = e.returncode
        output = e.output
    return returncode, output


@pytest.mark.skipif(not ipv6_available(), reason="IPv6 networking not available")
def test_validating_resolver():
    returncode, output = docker_compose_exec(
        "app",
        "ldns-dane -n -T verify internet.nl 443 -r $(getent ahostsv4 resolver-validating|grep STREAM|cut -d' ' -f1)",
    )
    print(output)
    assert "dane-validated successfully" in output
    assert returncode == 0
