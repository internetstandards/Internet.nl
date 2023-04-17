"""Basis functionality that should always be present."""
import pytest
from datetime import timedelta
from ..conftest import Internetnl
from bs4 import Tag
import time
import requests

TEST_DOMAIN = "test-target.internet.nl"
ALL_PROBES = {"ipv6", "dnssec", "tls", "appsecpriv", "rpki"}
TEST_DOMAIN_EXPECTED_SCORE = 100
TEST_DOMAIN_EXPECTED_SCORE = 64

TEST_EMAIL = "internet.nl"
ALL_EMAIL_PROBES = {"ipv6", "dnssec", "tls", "auth", "rpki"}
TEST_EMAIL_EXPECTED_SCORE = 100
TEST_EMAIL_EXPECTED_SCORE = 60

TEST_CONNECTION_EXPECTED_SCORE = 100

FOOTER_TEXT = "Internet.nl is an initiative of the Internet community and the Dutch"


PROBE_TIMEOUT = timedelta(minutes=5)
PROBE_INTERVAL = timedelta(seconds=5)
PROBE_TRIES = PROBE_TIMEOUT.seconds/PROBE_INTERVAL.seconds

@pytest.mark.withoutresponses
def test_index_http_ok(internetnl):
    assert internetnl.get('/').response.status_code == 200

@pytest.mark.withoutresponses
def test_index_footer_text_present(internetnl):
    assert FOOTER_TEXT in internetnl.get('/').response.text

@pytest.mark.withoutresponses
def test_reject_invalid_domain(internetnl, unique_id):
    domain = "invalid-domain.example.com"
    r = internetnl.post(f'/site/', data="url={domain}")
    assert r.response.is_redirect
    redirect_location = r.response.headers.get('Location')
    assert redirect_location == f"/test-site/?invalid"

@pytest.mark.withoutresponses
def test_your_website(internetnl: Internetnl, unique_id, test_domain=TEST_DOMAIN):
    """Runs the 'Test your website' test against the test target and expects a decent result."""

    r = internetnl.post('/site/', data={"url":test_domain})
    assert r.response.is_redirect
    probe_location = r.response.headers.get('Location')
    assert probe_location == f"/site/{test_domain}/", "Site is not redirecting to correct page"

    r = internetnl.post(probe_location, data={"url":test_domain})

    continue_location: str = str(r.soup.find("a", {"id":'continue'}).get("href"))
    assert continue_location == probe_location, "Expecting redirect to scan in progress, not results"

    probes = r.soup.find_all(class_='probe-name')
    assert {tag.text for tag in probes} == set(ALL_PROBES), "Mismatch in expected probes performed"

    # wait for probes to to complete
    for i in range(int(PROBE_TRIES)):
        time.sleep(PROBE_INTERVAL.seconds)

        r = internetnl.post(continue_location)
        continue_location = r.soup.find("a", {"id":'continue'}).get("href")
        if continue_location == "results":
            break
    else:
        assert 0, "Never redirected to results"

    r = internetnl.post(f"/site/{test_domain}/results")
    assert r.response.is_redirect
    result_location = r.response.headers.get('Location')

    r = internetnl.post(result_location)

    score = r.soup.find(class_="testresults-percentage").get("data-resultscore")
    assert int(score) == TEST_DOMAIN_EXPECTED_SCORE

    # TODO: when fully simulated integration test environment
    # probe_results = {}
    # for probe in ALL_PROBES:
    #      probe_results[probe] = r.soup.find(id=f"site{probe}").get("class")[0]
    # assert probe_results == {probe: "passed" for probe in ALL_PROBES}

@pytest.mark.withoutresponses
def test_your_email(internetnl: Internetnl, unique_id, test_email=TEST_EMAIL):
    """Runs the 'Test your email' and expects a decent result."""

    r = internetnl.post('/mail/', data={"url":test_email})
    assert r.response.is_redirect
    probe_location = r.response.headers.get('Location')
    assert probe_location == f"/mail/{test_email}/", "Site is not redirecting to correct page"

    r = internetnl.post(probe_location, data={"url":test_email})

    continue_location: str = str(r.soup.find("a", {"id":'continue'}).get("href"))
    assert continue_location == probe_location, "Expecting redirect to scan in progress, not results"

    probes = r.soup.find_all(class_='probe-name')
    assert {tag.text for tag in probes} == set(ALL_EMAIL_PROBES), "Mismatch in expected probes performed"

    # wait for probes to to complete
    for i in range(int(PROBE_TRIES)):
        time.sleep(PROBE_INTERVAL.seconds)

        r = internetnl.post(continue_location)
        continue_location = r.soup.find("a", {"id":'continue'}).get("href")
        if continue_location == "results":
            break
    else:
        assert 0, "Never redirected to results"

    r = internetnl.post(f"/mail/{test_email}/results")
    assert r.response.is_redirect
    result_location = r.response.headers.get('Location')

    r = internetnl.post(result_location)

    score = r.soup.find(class_="testresults-percentage").get("data-resultscore")
    assert int(score) == TEST_EMAIL_EXPECTED_SCORE

    # TODO: when fully simulated integration test environment
    # probe_results = {}
    # for probe in ALL_EMAIL_PROBES:
    #      probe_results[probe] = r.soup.find(id=f"mail{probe}").get("class")[0]
    # assert probe_results == {probe: "passed" for probe in ALL_EMAIL_PROBES}

@pytest.mark.withoutresponses
def test_your_connection(internetnl: Internetnl, browser, unique_id):
    """Runs the 'Test your connection' and expects a decent result."""

    timestamp = str(time.time()).replace(".", "")

    # initiate the test
    r = internetnl.get(f'/connection/gettestid/?_={timestamp}')
    test_id = r.response.json()["test_id"]
    print("test_id: " + test_id)

    # cause DNS lookups to be cached in redis
    browser.visit(f"http://{test_id}.aaaa.conn.test-ns-signed.internet.nl")
    browser.visit(f"http://{test_id}.a.conn.test-ns-signed.internet.nl")
    browser.visit(f"http://{test_id}.a-aaaa.conn.test-ns6-signed.internet.nl")
    # make actual ipv6 connection to testserver
    browser.visit(f"http://internet.nl/connection/addr-test/{test_id}/")

    # get results
    r = internetnl.get(f'/connection/finished/{test_id}?_={timestamp}')
    print(r.response.json())

    r = internetnl.get(f'/connection/{test_id}/results?_={timestamp}')
    score = r.soup.find(class_="testresults-percentage").get("data-resultscore")
    assert float(score) == TEST_CONNECTION_EXPECTED_SCORE
