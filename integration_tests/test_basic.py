"""Basis functionality that should always be present."""
import pytest
from datetime import timedelta
from .conftest import Internetnl
from bs4 import Tag
import time

TEST_DOMAIN = "example.com"
TEST_DOMAIN_EXPECTED_SCORE = 92

FOOTER_TEXT = "Internet.nl is an initiative of the Internet community and the Dutch"

ALL_PROBES = {"ipv6", "dnssec", "tls", "appsecpriv", "rpki"}

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
def test_basic_scan(internetnl: Internetnl, unique_id, domain=TEST_DOMAIN):
    r = internetnl.post('/site/', data={"url":domain})
    assert r.response.is_redirect
    probe_location = r.response.headers.get('Location')
    assert probe_location == f"/site/{domain}/", "Site is not redirecting to correct page"

    r = internetnl.post(probe_location, data={"url":domain})

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

    r = internetnl.post(f"/site/{domain}/results")
    assert r.response.is_redirect
    result_location = r.response.headers.get('Location')

    r = internetnl.post(result_location)

    score = r.soup.find(class_="testresults-percentage").get("data-resultscore")
    assert int(score) == TEST_DOMAIN_EXPECTED_SCORE

    probe_results = {}
    for probe in ALL_PROBES:
         probe_results[probe] = r.soup.find(id=f"site{probe}").get("class")[0]
    assert probe_results == {probe: "passed" for probe in ALL_PROBES}
