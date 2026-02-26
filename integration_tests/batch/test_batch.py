import requests
import pytest
import time
import json
from .results import EXPECTED_DOMAIN_RESULTS, EXPECTED_DOMAIN_TECHNICAL_RESULTS
from ..conftest import APP_DOMAIN
from playwright.sync_api import expect

INTERNETNL_API = f"https://{APP_DOMAIN}/api/batch/v2/"

TEST_DOMAIN = "target.test"
TEST_DOMAIN_EXPECTED_SCORE = 100
# TODO: improve test environment to allow 100% score result
TEST_DOMAIN_EXPECTED_SCORE = 54


BATCH_PERIODIC_TESTS_PREFIX = "batch periodic tests"


def wait_for_request_status(url, expected_status, timeout=10, interval=1, auth=None):
    """Poll url and parse JSON for request.status, return if value matches expected status or
    fail when timeout expires."""
    max_tries = int(timeout / interval)

    tries = 0
    while tries < max_tries:
        status_response = requests.get(url, auth=auth, verify=False)
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


@pytest.mark.parametrize(
    "path",
    [
        "requests",
        "requests/414878c6bde74343bcbf6a14de7d62de",
        "requests/414878c6bde74343bcbf6a14de7d62de/results",
        "/",
        "/site",
        "/mail",
    ],
)
def test_batch_requires_auth(path):
    """Batch API endpoints and certain pages should be behind authentication."""
    response = requests.post(INTERNETNL_API + path, json={}, verify=False)
    assert response.status_code == 401


def test_batch_openapi(page):
    """Open API documentation should be accessible without auth."""

    response = page.request.get(f"https://{APP_DOMAIN}/api/batch/openapi.yaml")
    expect(response).to_be_ok()


def test_batch_request(unique_id, register_test_user, test_domain, docker_compose_exec):
    """A test via the Batch API should succeed."""
    request_data = {"type": "web", "domains": [test_domain], "name": unique_id}

    auth = register_test_user

    # start batch request
    register_response = requests.post(INTERNETNL_API + "requests", json=request_data, auth=auth, verify=False)
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
    results_response = requests.get(INTERNETNL_API + "requests/" + test_id + "/results", auth=auth, verify=False)
    results_response.raise_for_status()
    print("api results JSON:", results_response.text)

    # compare results with expected results
    results_response_data = results_response.json()
    print("domain results JSON:", json.dumps(results_response_data["domains"][test_domain]["results"], indent=2))
    assert results_response_data["domains"][test_domain]["results"] == EXPECTED_DOMAIN_RESULTS

    # get batch technical results
    results_technical_response = requests.get(
        INTERNETNL_API + "requests/" + test_id + "/results_technical", auth=auth, verify=False
    )
    results_technical_response.raise_for_status()

    # compare results technical with expected response
    domain_technical_results = results_technical_response.json()["domains"][test_domain]
    print("domain technical results:", results_technical_response.json()["domains"][test_domain])
    expected_domain_technical_results = EXPECTED_DOMAIN_TECHNICAL_RESULTS
    expected_domain_technical_results["webservers"]["ipv4"]["details"]["securitytxt_found_host"] = test_domain
    expected_domain_technical_results["webservers"]["ipv6"]["details"]["securitytxt_found_host"] = test_domain
    assert domain_technical_results == expected_domain_technical_results

    # score and status should match expectations
    assert results_response_data["domains"][test_domain]["status"] == "ok"
    assert results_response_data["domains"][test_domain]["scoring"]["percentage"] == TEST_DOMAIN_EXPECTED_SCORE

    assert results_response_data["domains"][test_domain]["report"]["url"].startswith(
        "https"
    ), "Report URL should take procotol from request (https)"

    # test results page should be publicly accessible
    report_url = results_response_data["domains"][test_domain]["report"]["url"]
    response = requests.get(report_url, verify=False)
    assert response.status_code == 200, "test results should be publicly accessible without authentication"

    # delete result files (this can happen in production when cleanup is done by a cron job)
    docker_compose_exec("app", "sh -c 'rm -v /app/batch_results/*'")

    # try to get batch results again after files have been deleted (this should trigger a new generation task)
    results_response = requests.get(INTERNETNL_API + "requests/" + test_id + "/results", auth=auth, verify=False)
    # expect error because result need to be generated again
    assert results_response.status_code == 400
    assert "Report is being generated." in results_response.text

    # wait for report generation and batch to be done
    wait_for_request_status(INTERNETNL_API + "requests/" + test_id, "done", timeout=60, auth=auth)

    # get batch results again after starting generation
    results_response = requests.get(INTERNETNL_API + "requests/" + test_id + "/results", auth=auth, verify=False)
    print(f"{results_response.text=}")
    results_response.raise_for_status()
    print("api results JSON:", results_response.text)


def test_batch_static_requires_no_auth():
    """Static files should be available without authentication for viewing batch results."""
    response = requests.get(f"https://{APP_DOMAIN}/static/js/menu-min.js", json={}, verify=False)
    assert response.status_code == 200


def test_cron_delete_batch_results(trigger_cron, docker_compose_exec):
    """Test if batch results are compressed and deleted."""

    # create an 'old' batch results
    docker_compose_exec("cron", "touch -d '1999-03-31' /app/batch_results/test.json")

    trigger_cron("daily/delete_batch_results")

    assert not docker_compose_exec("cron", "ls /app/batch_results/test.json", check=False)
    assert docker_compose_exec("cron", "ls /app/batch_results/test.json.gz")

    # make the compressed batch result old
    docker_compose_exec("cron", "touch -d '1999-03-31' /app/batch_results/test.json.gz")

    trigger_cron("daily/delete_batch_results")

    assert not docker_compose_exec("cron", "ls /app/batch_results/test.json", check=False)
    assert not docker_compose_exec("cron", "ls /app/batch_results/test.json.gz", check=False)


def test_batch_db_cleanup(unique_id, trigger_cron, register_test_user, test_domain):
    """A test via the Batch API should succeed."""
    request_data = {"type": "web", "domains": [test_domain], "name": f"{BATCH_PERIODIC_TESTS_PREFIX} {unique_id}"}

    auth = register_test_user

    # start batch request
    register_response = requests.post(INTERNETNL_API + "requests", json=request_data, auth=auth, verify=False)
    register_data = register_response.json()
    test_id = register_data["request"]["request_id"]
    wait_for_request_status(INTERNETNL_API + "requests/" + test_id, "done", timeout=60, auth=auth)

    # generate batch results
    results_response = requests.get(INTERNETNL_API + "requests/" + test_id + "/results", auth=auth, verify=False)
    results_response.raise_for_status()
    assert not results_response.json() == {}

    # run db clean
    trigger_cron("daily/database_cleanup", service="cron-docker", suffix="-docker")

    # check batch results are gone
    results_response_after_cleanup = requests.get(
        INTERNETNL_API + "requests/" + test_id + "/results", auth=auth, verify=False
    )
    assert results_response_after_cleanup.json().get("error", {}).get("label", "") == "unknown-request"
