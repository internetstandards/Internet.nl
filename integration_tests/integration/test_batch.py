import requests
import pytest
import subprocess
import time
import json

INTERNETNL_API = "http://internet.test/api/batch/v2/"

TEST_DOMAIN = "target.test"
TEST_DOMAIN_EXPECTED_SCORE = 100
# TODO: improve test environment to allow 100% score result
TEST_DOMAIN_EXPECTED_SCORE = 48


def wait_for_request_status(url, expected_status, timeout=10, interval=1, auth=None):
    """Poll url and parse JSON for request.status, return if value matches expected status or
    fail when timeout expires."""
    max_tries = int(timeout / interval)

    tries = 0
    while tries < max_tries:
        status_response = requests.get(url, auth=auth)
        status_response.raise_for_status()

        print(status_response.text)
        status_data = status_response.json()
        if status_data["request"]["status"] == expected_status:
            break
        time.sleep(interval)
        tries += 1
    else:
        assert False, f"request status never reached '{expected_status}' state"

    return status_data


@pytest.fixture(scope="session")
def register_test_user(unique_id):
    """Register user that can login on the batch API."""

    username = f"int-test-{unique_id}"
    name = f"integration-tests-user-{unique_id}"
    organization = "integration-test"
    email = f"{username}@internet.test"

    # create test user in Django DB
    command = (
        f'docker compose --ansi=never --env-file "test.env" --project-name "internetnl-test"'
        f" exec app ./manage.py api_users register -u {username} -n {name} -o {organization} -e {email}"
    )
    subprocess.check_call(command, shell=True, universal_newlines=True)

    # create test used in Apache2 password file
    command = (
        f'docker compose --ansi=never --env-file "test.env" --project-name "internetnl-test"'
        f" exec webserver htpasswd -cb /usr/local/apache2/htpasswd {username} {username}"
    )
    subprocess.check_call(command, shell=True, universal_newlines=True)

    # for testing password is the same as username
    yield (username, username)


@pytest.mark.parametrize(
    "path",
    ["requests", "requests/414878c6bde74343bcbf6a14de7d62de", "requests/414878c6bde74343bcbf6a14de7d62de/results"],
)
def test_batch_requires_auth(path):
    response = requests.post(INTERNETNL_API + path, json={})
    assert response.status_code == 401


def test_batch_request(unique_id, register_test_user, test_domain):
    request_data = {"type": "web", "domains": [test_domain], "name": unique_id}

    auth = register_test_user

    # start batch request
    register_response = requests.post(INTERNETNL_API + "requests", json=request_data, auth=auth)
    register_response.raise_for_status()
    print(register_response.text)

    # assert batch request start response
    register_data = register_response.json()
    assert register_data["request"]["name"] == unique_id
    assert register_data["request"]["request_type"] == "web"
    assert register_data["request"]["status"] == "registering"

    test_id = register_data["request"]["request_id"]

    # wait for batch tests to start
    wait_for_request_status(INTERNETNL_API + "requests/" + test_id, "running", timeout=10, auth=auth)

    # wait for batch tests to complete and report to be generated
    wait_for_request_status(INTERNETNL_API + "requests/" + test_id, "generating", interval=2, timeout=120, auth=auth)

    # wait for report generation and batch to be done
    wait_for_request_status(INTERNETNL_API + "requests/" + test_id, "done", timeout=60, auth=auth)

    # get batch results
    results_response = requests.get(INTERNETNL_API + "requests/" + test_id + "/results", auth=auth)
    results_response.raise_for_status()
    print(results_response.text)

    # assert batch results contents
    results_response_data = results_response.json()
    print(json.dumps(results_response_data["domains"][test_domain]["results"], indent=2))
    assert results_response_data["domains"][test_domain]["status"] == "ok"
    assert results_response_data["domains"][test_domain]["scoring"]["percentage"] == TEST_DOMAIN_EXPECTED_SCORE

    # get batch technical results
    results_technical_response = requests.get(INTERNETNL_API + "requests/" + test_id + "/results_technical", auth=auth)
    results_technical_response.raise_for_status()
    print(results_technical_response.text)

    # assert batch technical results
    results_technical_response_data = results_technical_response.json()
    print(json.dumps(results_technical_response_data["domains"][test_domain], indent=2))
    assert results_technical_response_data["domains"][test_domain]["status"] == "ok"
    assert results_technical_response_data["domains"][test_domain]["webservers"]["ipv6"]["https_enabled"] is True
