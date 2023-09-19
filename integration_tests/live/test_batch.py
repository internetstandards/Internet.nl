import requests
import pytest
import time
import json

TEST_DOMAIN = "target.test"
TEST_DOMAIN_EXPECTED_SCORE = 100

# default production batch instances scheduler interval is 20 seconds
TIMEOUT = 60


@pytest.mark.parametrize(
    "path",
    ["requests", "requests/414878c6bde74343bcbf6a14de7d62de", "requests/414878c6bde74343bcbf6a14de7d62de/results"],
)
def test_batch_requires_auth(path, api_auth, api_url):
    response = requests.post(api_url + path, json={}, verify=False)
    assert response.status_code == 401


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


def test_batch_request(unique_id, api_auth, test_domain, api_url):
    request_data = {"type": "web", "domains": [test_domain], "name": unique_id}

    auth = api_auth

    # start batch request
    register_response = requests.post(api_url + "requests", json=request_data, auth=auth, verify=False)
    register_response.raise_for_status()
    print(register_response.text)

    # assert batch request start response
    register_data = register_response.json()
    assert register_data["request"]["name"] == unique_id
    assert register_data["request"]["request_type"] == "web"
    assert register_data["request"]["status"] == "registering"

    test_id = register_data["request"]["request_id"]

    # wait for batch tests to start
    wait_for_request_status(api_url + "requests/" + test_id, "running", timeout=TIMEOUT, auth=auth)

    # wait for batch tests to complete and report to be generated
    wait_for_request_status(api_url + "requests/" + test_id, "generating", interval=2, timeout=2 * TIMEOUT, auth=auth)

    # wait for report generation and batch to be done
    wait_for_request_status(api_url + "requests/" + test_id, "done", timeout=TIMEOUT, auth=auth)

    # get batch results
    results_response = requests.get(api_url + "requests/" + test_id + "/results", auth=auth, verify=False)
    results_response.raise_for_status()
    print(results_response.text)

    # assert batch results contents
    results_response_data = results_response.json()
    print(json.dumps(results_response_data["domains"][test_domain]["results"], indent=2))
    assert results_response_data["domains"][test_domain]["status"] == "ok"
    assert results_response_data["domains"][test_domain]["scoring"]["percentage"] == TEST_DOMAIN_EXPECTED_SCORE

    # get batch technical results
    results_technical_response = requests.get(
        api_url + "requests/" + test_id + "/results_technical", auth=auth, verify=False
    )
    results_technical_response.raise_for_status()
    print(results_technical_response.text)

    # assert batch technical results
    results_technical_response_data = results_technical_response.json()
    print(json.dumps(results_technical_response_data["domains"][test_domain], indent=2))
    assert results_technical_response_data["domains"][test_domain]["status"] == "ok"
    assert results_technical_response_data["domains"][test_domain]["webservers"]["ipv6"]["https_enabled"] is True
