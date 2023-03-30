"""Test against live instances."""
import pytest
from datetime import timedelta
from ..conftest import Internetnl
from bs4 import Tag
import time
import requests
from urllib.parse import urlparse
import socket

# domain to use as target for website and email tests
TEST_DOMAIN = 'internet.nl'
ALL_PROBES = {"ipv6", "dnssec", "tls", "appsecpriv", "rpki"}
TEST_DOMAIN_EXPECTED_SCORE = 100

TEST_EMAIL = "internet.nl"
ALL_EMAIL_PROBES = {"ipv6", "dnssec", "tls", "auth", "rpki"}
TEST_EMAIL_EXPECTED_SCORE = 100

TEST_CONNECTION_EXPECTED_SCORE = 100

# instances of internet.nl to test against
TEST_INSTANCES = ['internet.nl', 'locohost.nl']

# this text is expected to be on the index page when it is fully rendered
FOOTER_TEXT = "Internet.nl is an initiative of the Internet community and the Dutch"

PROBE_TIMEOUT = timedelta(minutes=5)
PROBE_INTERVAL = timedelta(seconds=5)
PROBE_TRIES = PROBE_TIMEOUT.seconds/PROBE_INTERVAL.seconds

IPV6_TEST_DOMAIN = TEST_DOMAIN

def ipv6_connectivity():
    ipv6_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, 0)
    try:
        ipv6_socket.connect((IPV6_TEST_DOMAIN, 80))
        return True
    except:
        return False

@pytest.mark.withoutresponses
@pytest.mark.parametrize("internetnl_live", TEST_INSTANCES, indirect=True)
def test_index_http_ok(internetnl_live):
    assert internetnl_live.get('/').response.status_code == 200

@pytest.mark.withoutresponses
@pytest.mark.parametrize("internetnl_live", TEST_INSTANCES, indirect=True)
def test_index_footer_text_present(internetnl_live):
    assert FOOTER_TEXT in internetnl_live.get('/').response.text

@pytest.mark.withoutresponses
@pytest.mark.parametrize("internetnl_live", TEST_INSTANCES, indirect=True)
def test_reject_invalid_domain(internetnl_live, unique_id):
    domain = "invalid-domain.example.com"
    r = internetnl_live.post(f'/site/', data="url={domain}")
    assert r.response.is_redirect
    redirect_location = r.response.headers.get('Location')
    assert redirect_location == f"/test-site/?invalid"

@pytest.mark.withoutresponses
@pytest.mark.parametrize("internetnl_live", TEST_INSTANCES, indirect=True)
def test_your_website(internetnl_live: Internetnl, test_domain=TEST_DOMAIN):
    """Runs the 'Test your website' test against the test target and expects a decent result."""

    r = internetnl_live.post('/site/', data={"url":test_domain})
    assert r.response.is_redirect
    probe_location = r.response.headers.get('Location')
    assert probe_location == f"/site/{test_domain}/", "Site is not redirecting to correct page"

    # wait for probes to to complete
    r = internetnl_live.post(probe_location, data={"url":test_domain})
    continue_location: str = str(r.soup.find("a", {"id":'continue'}).get("href"))
    if not continue_location == 'results':
        for i in range(int(PROBE_TRIES)):
            time.sleep(PROBE_INTERVAL.seconds)

            r = internetnl_live.post(continue_location)
            continue_location = r.soup.find("a", {"id":'continue'}).get("href")
            if continue_location == "results":
                break
        else:
            assert 0, "Never redirected to results"

    r = internetnl_live.post(f"/site/{test_domain}/results")
    assert r.response.is_redirect
    result_location = r.response.headers.get('Location')

    # get results
    r = internetnl_live.post(result_location)

    # verify score
    score = r.soup.find(class_="testresults-percentage").get("data-resultscore")
    assert int(score) == TEST_DOMAIN_EXPECTED_SCORE

    # verify probe results
    probe_results = {}
    for probe in ALL_PROBES:
         probe_results[probe] = r.soup.find(id=f"site{probe}").get("class")[0]
    assert probe_results == {probe: "passed" for probe in ALL_PROBES}

@pytest.mark.withoutresponses
@pytest.mark.parametrize("internetnl_live", TEST_INSTANCES, indirect=True)
def test_your_email(internetnl_live: Internetnl, test_email=TEST_EMAIL):
    """Runs the 'Test your email' and expects a decent result."""

    r = internetnl_live.post('/mail/', data={"url":test_email})
    assert r.response.is_redirect
    probe_location = r.response.headers.get('Location')
    assert probe_location == f"/mail/{test_email}/", "Site is not redirecting to correct page"

    # wait for probes to to complete
    r = internetnl_live.post(probe_location, data={"url":test_email})
    continue_location: str = str(r.soup.find("a", {"id":'continue'}).get("href"))
    if not continue_location == 'results':
        for i in range(int(PROBE_TRIES)):
            time.sleep(PROBE_INTERVAL.seconds)

            r = internetnl_live.post(continue_location)
            continue_location = r.soup.find("a", {"id":'continue'}).get("href")
            if continue_location == "results":
                break
        else:
            assert 0, "Never redirected to results"

    r = internetnl_live.post(f"/mail/{test_email}/results")
    assert r.response.is_redirect
    result_location = r.response.headers.get('Location')

    # get results
    r = internetnl_live.post(result_location)

    # verify score
    score = r.soup.find(class_="testresults-percentage").get("data-resultscore")
    assert int(score) == TEST_EMAIL_EXPECTED_SCORE

    # verify probe results
    probe_results = {}
    for probe in ALL_EMAIL_PROBES:
         probe_results[probe] = r.soup.find(id=f"mail{probe}").get("class")[0]
    assert probe_results == {probe: "passed" for probe in ALL_EMAIL_PROBES}

@pytest.mark.withoutresponses
@pytest.mark.parametrize("internetnl_live", TEST_INSTANCES, indirect=True)
def test_your_connection(internetnl_live: Internetnl, request):
    """Runs the 'Test your connection' and expects a decent result."""
    if not ipv6_connectivity():
        pytest.skip("need IPv6 connectivity")

    test_instance = urlparse(internetnl_live.url).netloc

    timestamp = str(time.time()).replace(".", "")

    # initiate the test
    r = internetnl_live.get(f'/connection/gettestid/?_={timestamp}')
    test_id = r.response.json()["test_id"]
    print("test_id: " + test_id)

    # cause DNS lookups to be cached in redis
    requests.get(f"http://{test_id}.aaaa.conn.test-ns-signed.{test_instance}")
    requests.get(f"http://{test_id}.a.conn.test-ns-signed.{test_instance}")
    requests.get(f"http://{test_id}.a-aaaa.conn.test-ns6-signed.{test_instance}")
    # make actual ipv6 connection to testserver
    requests.get(f"http://{test_instance}/connection/addr-test/{test_id}/")

    # get results
    r = internetnl_live.get(f'/connection/finished/{test_id}?_={timestamp}')
    print(r.response.json())

    r = internetnl_live.get(f'/connection/{test_id}/results?_={timestamp}')
    score = r.soup.find(class_="testresults-percentage").get("data-resultscore")
    assert float(score) == TEST_CONNECTION_EXPECTED_SCORE
