#!/usr/bin/env python3

# run tests on example domains and write metrics to prometheus textfile

# for iterative development
# docker run -ti -e INTERNETNL_DOMAINNAME=internet.nl -v $PWD/docker/cron/periodic/15min/tests.py:/tests.py \
# ghcr.io/internetstandards/util:latest /tests.py --debug

import sys
import os
import time
from prometheus_client import REGISTRY, Gauge, generate_latest
import prometheus_client
import logging
import requests

log = logging.getLogger(__name__)

DEBUG = "--debug" in sys.argv

# file to write metrics to https://github.com/prometheus/node_exporter?tab=readme-ov-file#textfile-collector
OUTPUT_TEXTFILE = "/prometheus-textfile-directory/tests.prom"


DEFAULT_TEST_TIMEOUT = 200
TEST_TIMEOUT = int(os.environ.get("INTERNETNL_CACHE_TTL", DEFAULT_TEST_TIMEOUT))
REQUEST_TIMEOUT = 30

INTERNETNL_DOMAINNAME = os.environ.get("INTERNETNL_DOMAINNAME")
# talk directly to the internal app container as the webserver might
# have access restrictions in place
URL_BASE = "http://app:8080"
HEADERS = {"Host": INTERNETNL_DOMAINNAME}

TESTS = ["site", "mail"]

TEST_DOMAINS = dict()
TEST_DOMAINS["site"] = [v.strip() for v in os.environ.get("TEST_DOMAINS_SITE", "").split(",") if v]
TEST_DOMAINS["mail"] = [v.strip() for v in os.environ.get("TEST_DOMAINS_MAIL", "").split(",") if v]

METRIC_PROBE_DONE = Gauge("tests_probe_done_total", "Whether the probe completed.", ["test", "domain", "probe"])
METRIC_PROBE_SUCCESS = Gauge("tests_probe_success_total", "Whether the probe succeeded.", ["test", "domain", "probe"])
METRIC_PROBE_RUNTIME = Gauge(
    "tests_probe_runtime_seconds", "Amount of time probe ran before done.", ["test", "domain", "probe"]
)
METRIC_PROBE_SCORE = Gauge("tests_probe_score", "Score of the probe.", ["test", "domain", "probe"])
METRIC_PROBE_PASSED = Gauge("tests_probe_pass", "Probe has passed.", ["test", "domain", "probe"])

METRIC_TEST_RUN = Gauge("tests_test_run_total", "Test that have been run.", ["test", "domain"])
METRIC_TEST_CACHE = Gauge("tests_test_cached_total", "Test runs that returned cached results.", ["test", "domain"])
METRIC_TEST_FAILURE = Gauge("tests_test_failure_total", "Test runs that failed.", ["test", "domain"])
METRIC_TEST_SUCCESS = Gauge("tests_test_success_total", "Test runs that succeeded.", ["test", "domain"])
METRIC_TEST_TIMEOUT = Gauge("tests_test_timeout_total", "Test that ran into timeout.", ["test", "domain"])
METRIC_TEST_RUNTIME = Gauge("tests_test_runtime_seconds", "Amount of time test ran before done.", ["test", "domain"])
METRIC_TEST_SCORE = Gauge("tests_test_score", "Total score of all probes in the test.", ["test", "domain"])


def run_tests_on_domain(test, domain):
    test_start = int(time.time())

    # initiate the test
    r = requests.get(
        f"{URL_BASE}/{test}/probes/{domain}/?{time.time()}",
        timeout=REQUEST_TIMEOUT,
        allow_redirects=False,
        headers=HEADERS,
    )
    r.raise_for_status()
    log.debug(r.text)

    # abort early if cached result
    probes = r.json()
    if not [p for p in probes if not p["done"]]:
        METRIC_TEST_CACHE.labels(test, domain).set(1)
        return

    # poll probes until done
    finished_probes = set()
    while int(time.time()) < test_start + TEST_TIMEOUT:
        # get probe status
        r = requests.get(
            f"{URL_BASE}/{test}/probes/{domain}/?{time.time()}",
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
            headers=HEADERS,
        )
        r.raise_for_status()
        log.debug(r.text)

        # record probe statuses for probes that are finished
        probes = r.json()
        for probe in probes:
            if probe["name"] in finished_probes:
                continue
            METRIC_PROBE_DONE.labels(test, domain, probe["name"]).set(probe["done"])
            if probe["done"]:
                METRIC_PROBE_SUCCESS.labels(test, domain, probe["name"]).set(probe["success"])
                METRIC_PROBE_RUNTIME.labels(test, domain, probe["name"]).set(int(time.time() - test_start))
                finished_probes.add(probe["name"])

        # stop when all probes are finished
        if not [p for p in probes if not p["done"]]:
            METRIC_TEST_SUCCESS.labels(test, domain).set(1)
            break

        time.sleep(1)
    else:
        # test timed out because one or more of the probes was not done within time
        METRIC_TEST_TIMEOUT.labels(test, domain).set(1)
        for probe in probes:
            if probe["name"] in finished_probes:
                continue
            # record not finished probes as failed
            METRIC_PROBE_DONE.labels(test, domain, probe["name"]).set(probe["done"])
            METRIC_PROBE_RUNTIME.labels(test, domain, probe["name"]).set(int(time.time() - test_start))
            if probe["done"]:
                METRIC_PROBE_SUCCESS.labels(test, domain, probe["name"]).set(probe["success"])

    METRIC_TEST_RUNTIME.labels(test, domain).set(int(time.time() - test_start))

    # get additional metrics like score
    scores = list()
    for probe_name in finished_probes:
        try:
            r = requests.get(
                f"{URL_BASE}/{test}/{probe_name}/{domain}/?{time.time()}",
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,
                headers=HEADERS,
            )
            r.raise_for_status()
            if r.status_code == 200:
                probe_result = r.json()
                # only measure probe scores that count towards total score
                if probe_result["maxscore"]:
                    METRIC_PROBE_SCORE.labels(test, domain, probe_name).set(probe_result["totalscore"])
                    scores.append(probe_result["totalscore"])
                METRIC_PROBE_PASSED.labels(test, domain, probe_name).set(probe_result["verdict"] == "passed")
        except Exception:
            log.exception("failed to get probe score")

    if scores:
        METRIC_TEST_SCORE.labels(test, domain).set(max(min(int(sum(scores) / len(scores)), 100), 0))
    else:
        METRIC_TEST_SCORE.labels(test, domain).set(0)


def run_tests():
    for test in TESTS:
        for domain in TEST_DOMAINS[test]:
            log.info(f"testing: {test} {domain}")
            METRIC_TEST_RUN.labels(test, domain).set(1)
            METRIC_TEST_CACHE.labels(test, domain).set(0)
            METRIC_TEST_FAILURE.labels(test, domain).set(0)
            METRIC_TEST_TIMEOUT.labels(test, domain).set(0)
            METRIC_TEST_SUCCESS.labels(test, domain).set(0)
            try:
                run_tests_on_domain(test, domain)
            except Exception:
                log.exception("Error during test")
                METRIC_TEST_FAILURE.labels(test, domain).set(1)


def main():
    logging.basicConfig(level=logging.DEBUG if DEBUG else logging.ERROR)

    # disable internal metrics
    REGISTRY.unregister(prometheus_client.GC_COLLECTOR)
    REGISTRY.unregister(prometheus_client.PLATFORM_COLLECTOR)
    REGISTRY.unregister(prometheus_client.PROCESS_COLLECTOR)

    # run test probes against domains and collect metrics
    run_tests()

    # write metrics to stdout or file in prometheus textfile format
    if DEBUG:
        print(generate_latest(REGISTRY).decode())
    else:
        with open(OUTPUT_TEXTFILE, "w") as f:
            f.write(generate_latest(REGISTRY).decode())


if __name__ == "__main__" and os.environ.get("CRON_15MIN_RUN_TESTS", "False") == "True":
    main()
