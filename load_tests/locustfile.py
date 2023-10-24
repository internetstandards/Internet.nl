#!/usr/bin/env python3
"""
This is a configuration file for Locust load tests.

It provides a balance of different types of visits and tests being performed on the Internet.nl website.

Run it using the following command:
    locust --headless --users 50 --spawn-rate 50 --run-time 10m --host https://docker.internet.nl

Where in this case it runs headless for 10 minutes simulating 50 simultaneous users.
"""

import time
from locust import FastHttpUser, run_single_user, task
import random

MAX_TEST_DURATION_S = 200
PROBES_INTERVAL_S = 3


class InternetnlStaticVisitor(FastHttpUser):
    """This class defines an average Internet.nl visitor which always enters through
    the frontpage and visits some of the subpages."""

    @task(10)
    def about(self):
        self.client.get("/")
        self.client.get("/about/")

    @task(10)
    def faqs(self):
        self.client.get("/")
        self.client.get("/faqs/")

    @task(10)
    def news(self):
        self.client.get("/")
        self.client.get("/news/")

    @task(10)
    def halloffame(self):
        self.client.get("/")
        self.client.get("/halloffame/")


class InternetnlTestingVisitor(FastHttpUser):
    """This class defines an Internet.nl visitor which enters through the frontpage
    and performs a test against a website."""

    @task(100)
    def start_test(self):
        """Run majority of tests against known working targets."""

        test_domain = random.choice(
            [
                # randomize url's to prevent server cached results
                *[f"a{random.randrange(1,9999999)}.test-ns-signed.dev.internet.nl"]
                * 30,
            ]
        )

        self.client.get("/")

        # start test
        self.client.post("/site/", {"url": test_domain}, name="/site/ (start test)")

        # wait for test to finish
        timeout = MAX_TEST_DURATION_S
        while True:
            if timeout < 0:
                break

            time.sleep(PROBES_INTERVAL_S)
            with self.client.get(
                f"/site/probes/{test_domain}?{time.time()}",
                catch_response=True,
                name="/site/probes/[test_domain] (wait for test finish)",
            ) as probe_response:
                try:
                    json = probe_response.json()
                except json.decoder.JSONDecodeError:
                    probe_response.failure("Failed to decode probe response")
                    continue

                if json and type(json) == list and all(x.get("done") for x in json):
                    break

            timeout -= PROBES_INTERVAL_S

        # get test result
        with self.client.get(
            f"/site/{test_domain}/results", catch_response=True, name="/site/[test_domain]/results (test results)"
        ) as result_response:
            if "data-resultscore" not in result_response.text:
                result_response.failure("no score/task did not complete in time")


class InternetnlTestingInvalidsVisitor(FastHttpUser):
    """This class defines an Internet.nl visitor which enters through the frontpage
    and performs tests against websites with issues."""

    @task(50)
    def website_test_invalids(self):
        """Test a number of domain's that have known issues. To simulate non-happy flows. These
        are not expected to succeed."""

        test_domain = random.choice(
            [
                "servfail.nl",
                "forfun.net",
                "brokendnssec.net",
                "expired.badssl.com",
                "wrong.host.badssl.com",
                "self-signed.badssl.com",
                "untrusted-root.badssl.com",
                "revoked.badssl.com",
                "pinning-test.badssl.com",
                "invalid.rpki.isbgpsafeyet.com",
            ]
        )

        self.client.get("/")

        # start test
        self.client.post("/site/", {"url": test_domain}, name="/site/ (start test, invalid)")

        # wait for test to finish
        timeout = MAX_TEST_DURATION_S
        while True:
            if timeout < 0:
                break

            time.sleep(PROBES_INTERVAL_S)
            with self.client.get(
                f"/site/probes/{test_domain}?{time.time()}",
                catch_response=True,
                name="/site/probes/[test_invalid_domain] (wait for test finish)",
            ) as probe_response:
                try:
                    json = probe_response.json()
                except json.decoder.JSONDecodeError:
                    probe_response.failure("Failed to decode probe response")
                    continue

                if json and type(json) == list and all(x.get("done") for x in json):
                    break

            timeout -= PROBES_INTERVAL_S

        # get test result, we won't assert on this as we expect some tests to fail
        self.client.get(
            f"/site/{test_domain}/results",
            catch_response=True,
            name="/site/[test_invalid_domain]/results (test results)",
        )


class InternetnlVisitor(InternetnlStaticVisitor, InternetnlTestingVisitor, InternetnlTestingInvalidsVisitor):
    pass


# run this file directly for debugging, eg: ./locustfile.py --users 100 --run-time 10m --host https://internet.nl
if __name__ == "__main__":
    run_single_user(InternetnlTestingVisitor)
