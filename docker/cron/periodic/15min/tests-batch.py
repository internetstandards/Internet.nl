#!/usr/bin/env python3

# run tests on example domains and write metrics to prometheus textfile

# for iterative development
# docker run -ti -e INTERNETNL_DOMAINNAME=internet.nl -v $PWD/docker/cron/periodic/15min/tests.py:/tests.py \
# ghcr.io/internetstandards/cron:latest /tests.py --debug

import sys
import os
import time
from prometheus_client import REGISTRY, Gauge, generate_latest
import prometheus_client
import logging
import requests
import datetime

log = logging.getLogger(__name__)

DEBUG = "--debug" in sys.argv

# file to write metrics to https://github.com/prometheus/node_exporter?tab=readme-ov-file#textfile-collector
OUTPUT_TEXTFILE = "/prometheus-textfile-directory/tests-batch.prom"


BATCH_REQUEST_TIMEOUT = 60 * 5
REQUEST_TIMEOUT = 30

REQUEST_TYPES = ["web", "mail"]

IPV4_IP_APP_INTERNAL = os.environ.get("IPV4_IP_APP_INTERNAL")
INTERNETNL_DOMAINNAME = os.environ.get("INTERNETNL_DOMAINNAME")
# talk directly to the internal app container as the webserver might
# have access restrictions in place
URL_BASE = f"http://{IPV4_IP_APP_INTERNAL}:8080"
HEADERS = {"Host": INTERNETNL_DOMAINNAME}

TEST_DOMAINS = {
    # domain's to use in website tests
    "web": [
        "internet.nl",
        "example.nl",
        "example.com",
        "internetsociety.org",
        "ripe.net",
        "surf.nl",
        "ecp.nl",
        "forumstandaardisatie.nl",
        "minez.nl",
    ],
    # domain's to use in mail tests
    "mail": [
        "internetsociety.org",
        "ripe.net",
        "surf.nl",
        "ecp.nl",
        # these are currently really slow and will probably improve when
        # we switch to sslyze, for now disable these in monitoring
        # "internet.nl",
        # "forumstandaardisatie.nl",
        # "minez.nl",
    ],
}

METRIC_BATCH_RUN = Gauge("tests_batch_run_total", "Batch requests that have been run.", ["request_type"])
METRIC_BATCH_SUCCESS = Gauge("tests_batch_success_total", "Batch requests runs that succeeded.", ["request_type"])
METRIC_BATCH_FAILURE = Gauge("tests_batch_failure_total", "Batch requests runs that failed.", ["request_type"])
METRIC_BATCH_TIMEOUT = Gauge("tests_batch_timeout_total", "Batch requests that ran into timeout.", ["request_type"])
METRIC_BATCH_RUNTIME = Gauge(
    "tests_batch_runtime_seconds", "Amount of time batch request ran before done.", ["request_type"]
)
METRIC_BATCH_STAGE_RUNTIME = Gauge(
    "tests_batch_stage_runtime_seconds", "Amount of time each stage in batch request took.", ["request_type", "stage"]
)

METRIC_BATCH_DOMAIN = Gauge("tests_batch_domain_total", "Amount of domains batch request.", ["request_type", "domain"])

METRIC_BATCH_DOMAIN_SUCCESS = Gauge(
    "tests_batch_domain_success",
    "Amount of successful domain tests in batch request per domain.",
    ["request_type", "domain"],
)
METRIC_BATCH_DOMAIN_SCORE = Gauge(
    "tests_batch_domain_score", "Per domain test scores for batch request.", ["request_type", "domain"]
)

METRIC_BATCH_DOMAIN_CATEGORIES = Gauge(
    "tests_batch_domain_categories",
    "Domain verdict and status per category.",
    ["request_type", "domain", "category", "verdict", "status"],
)

METRIC_BATCH_DOMAIN_TESTS = Gauge(
    "tests_batch_domain_tests",
    "Domain verdict and status per test.",
    ["request_type", "domain", "test", "verdict", "status"],
)


def wait_for_request_status(url: str, expected_status: list[str], timeout: int = 10, interval: int = 1, auth=None):
    """Poll url and parse JSON for request.status, return if value matches expected status or
    fail when timeout expires."""

    log.debug("waiting for status: %s", expected_status)

    max_tries = int(timeout / interval)

    tries = 0
    status = "n/a"
    while tries < max_tries:
        status_response = requests.get(url, auth=auth, headers=HEADERS)
        status_response.raise_for_status()

        log.debug(status_response.text)
        status_data = status_response.json()
        status: str = status_data["request"]["status"]
        if status in expected_status:
            break
        time.sleep(interval)
        tries += 1
    else:
        raise TimeoutError(f"request status never reached '{str(expected_status)}' states, current state: '{status}'")


def run_test_batch(request_type: str, domains: list[str]):
    request_data = {"type": "web", "domains": domains, "name": f"periodic test {str(datetime.datetime.now())}"}

    auth = ("periodic_tests", "periodic_tests")
    api_url: str = URL_BASE + "/api/batch/v2/"

    test_start = int(time.time())

    # start batch request
    register_response = requests.post(api_url + "requests", json=request_data, auth=auth, headers=HEADERS)
    register_response.raise_for_status()
    log.debug(register_response.text)

    # get test_id from register data
    register_data = register_response.json()
    test_id: str = register_data["request"]["request_id"]

    # wait for batch tests to start
    wait_for_request_status(
        api_url + "requests/" + test_id, ["running", "generating", "done"], timeout=BATCH_REQUEST_TIMEOUT, auth=auth
    )
    registering_time = int(time.time()) - test_start
    METRIC_BATCH_STAGE_RUNTIME.labels(request_type, "registering").set(registering_time)

    # wait for batch tests to complete and report to be generated
    wait_for_request_status(
        api_url + "requests/" + test_id, ["generating", "done"], timeout=BATCH_REQUEST_TIMEOUT, auth=auth
    )
    running_time = int(time.time()) - test_start - registering_time
    METRIC_BATCH_STAGE_RUNTIME.labels(request_type, "running").set(running_time)

    # wait for report generation and batch to be done
    wait_for_request_status(api_url + "requests/" + test_id, ["done"], timeout=BATCH_REQUEST_TIMEOUT, auth=auth)
    generating_time = int(time.time()) - test_start - running_time
    METRIC_BATCH_STAGE_RUNTIME.labels(request_type, "generating").set(generating_time)

    # get batch results
    results_response = requests.get(api_url + "requests/" + test_id + "/results", auth=auth, headers=HEADERS)
    results_response.raise_for_status()
    log.debug(results_response.text)

    results_response_data = results_response.json()

    METRIC_BATCH_RUNTIME.labels(request_type).set(int(time.time() - test_start))
    METRIC_BATCH_SUCCESS.labels(request_type).set(1 if results_response_data["request"]["status"] == "done" else 0)

    for domain, results in results_response_data["domains"].items():
        METRIC_BATCH_DOMAIN.labels(request_type, domain).set(1)
        METRIC_BATCH_DOMAIN_SUCCESS.labels(request_type, domain).set(1 if results["status"] == "ok" else 0)
        METRIC_BATCH_DOMAIN_SCORE.labels(request_type, domain).set(results["scoring"]["percentage"])

        for category, result in results["results"]["categories"].items():
            METRIC_BATCH_DOMAIN_CATEGORIES.labels(
                request_type, domain, category, result["verdict"], result["status"]
            ).inc(1)

        for test, result in results["results"]["tests"].items():
            METRIC_BATCH_DOMAIN_TESTS.labels(request_type, domain, test, result["verdict"], result["status"]).inc(1)


def run_batch_tests():
    for request_type in REQUEST_TYPES:
        domains = TEST_DOMAINS[request_type]
        log.info(f"testing: {request_type} {domains}")

        METRIC_BATCH_RUN.labels(request_type).set(1)
        METRIC_BATCH_FAILURE.labels(request_type).set(0)
        METRIC_BATCH_TIMEOUT.labels(request_type).set(0)
        METRIC_BATCH_SUCCESS.labels(request_type).set(0)
        try:
            run_test_batch(request_type, domains)

        except Exception:
            log.exception("Error during test")
            METRIC_BATCH_FAILURE.labels(request_type).set(1)


def main():
    logging.basicConfig(level=logging.DEBUG if DEBUG else logging.ERROR)

    # disable internal metrics
    REGISTRY.unregister(prometheus_client.GC_COLLECTOR)
    REGISTRY.unregister(prometheus_client.PLATFORM_COLLECTOR)
    REGISTRY.unregister(prometheus_client.PROCESS_COLLECTOR)

    # run test probes against domains and collect metrics
    run_batch_tests()

    # write metrics to stdout or file in prometheus textfile format
    if DEBUG:
        print(generate_latest(REGISTRY).decode())
    else:
        with open(OUTPUT_TEXTFILE, "w") as f:
            f.write(generate_latest(REGISTRY).decode())


if __name__ == "__main__" and os.environ.get("CRON_15MIN_RUN_TESTS_BATCH", "False") == "True":
    main()
