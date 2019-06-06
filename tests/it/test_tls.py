# TODO: Use Selenium Page Objects
# Don't test the success percentage yet because the target servers use
# self-signed SSL certificates which do not pass the certificate trust
# chain test and thus we cannot achieve a 100% score. Also, a score of
# 100% doesn't say anything about how tests or which tests passed.

import logging
import pytest
import time
from selenium.webdriver.common.by import By
from selenium.common.exceptions import NoSuchElementException, TimeoutException
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC


logger = logging.getLogger(__name__)


BASE_URL = 'http://internet.nl:8080/'

LOCATOR_REPORT_SHOW_DETAILS_BUTTON_CLASS = 'panel-button-show'
LOCATOR_FAILED_TEST_CLASS = 'testresult failed'
LOCATOR_PROBING_CLASS = 'probing'
LOCATOR_PROBE_CATEGORY_SUFFIX = '-summary'
LOCATOR_PROBE_RUNNING_TEXT = 'Running...'
LOCATOR_WEBSITE_TEST_FORM_ID = 'web-url'
LOCATOR_RESULTS_OVERVIEW_ID = 'testresults-overview'
LOCATOR_PROGRESS_AND_RESULT_TITLE_PREFIX = 'Website test: '

TEST_CERT_TRUST = 'Trust chain of certificate'
TEST_IPV6_ADDRESS_FOR_WEB_SERVER = 'IPv6 addresses for web server'
TEST_DOMAIN_NAME_ON_CERT = 'Domain name on certificate'
TEST_HSTS = 'HSTS'
TEST_HTTPS_AVAILABLE = 'HTTPS available'
TEST_SAME_WEBSITE_ON_IPV4_AND_IPV6 = 'Same website on IPv6 and IPv4'

ALWAYS_EXPECTED_FAILURES = tuple([TEST_CERT_TRUST])


def get_failed_tests(pytest_test_id, selenium, expected_failures):
    testresult_failed_anchors = selenium.find_elements(
        By.XPATH, '//*[@class=\'{}\']/h3/a'.format(
            LOCATOR_FAILED_TEST_CLASS))

    failed_tests = []
    for title_anchor_of_failed_test in testresult_failed_anchors:
        # This element should be an anchor ('<a>') child of a <div> structure like so:
        # <div class='testresult_failed'>
        #   <h3 class='panel-title'>
        #     <a ..>
        #       <span class="visuallyhidden">Failed:</span>
        #       TEST TITLE
        #       <span class="pre-icon visuallyhidden">
        #
        #       open
        #
        #       </span>
        #       <span class="icon"><img src="/static/push-open.png" alt=""></span>
        #     </a>
        #   </h3>
        # We are interested in the TEST TITLE. We hope that WebElement.text() contains it.
        # Yeuch. The DOM elements don't always appear to be in the same order so we can't
        # just use the [1] line of text as sometimes that isn't TEST TITLE but is 'open'.
        internetnl_test_title = title_anchor_of_failed_test.text.replace("Failed:", '').replace("open", '').strip()

        if internetnl_test_title in expected_failures:
            # This print statement will only be visible if either pytest is
            # invoked using the -s argument, or if the pytest test case fails.
            logger.warning('In test {} ignoring "{}" failure as it is flagged as acceptable'.format(pytest_test_id, internetnl_test_title))
        else:
            failed_tests.append(internetnl_test_title)

    if failed_tests:
        for el in selenium.find_elements(By.CLASS_NAME, LOCATOR_REPORT_SHOW_DETAILS_BUTTON_CLASS):
            el.click()

    return failed_tests


def results_overview_is_present(selenium):
    try:
        if selenium.find_element_by_id(LOCATOR_RESULTS_OVERVIEW_ID):
            return True
    except NoSuchElementException:
        return False


def probes_are_running(seleniun):
    # While the test in-progress page is visible there will be a list of
    # in-progress or completed probes. When the test is finished either
    # all of the probes will have failed or the page will include a test
    # result overview, e.g.:
    #   <ul>
    #     <li class="probing">
    #       <strong>Secure connection?</strong>
    #       <br>
    #       <img ...>
    #       <span id="tls-summary" ...>
    #       PROBE STATUS
    #       </span>
    #     </li>
    # We are interested in PROBE STATUS.
    # Yeuch.
    # XPath 'ends-with' would be better than contains but is only
    # supported in XPath 2.0+ while Selenium/Browsers only support
    # XPath 1.0.
    try:
        if seleniun.find_element_by_xpath(
            '//*[@class=\'{}\']/span[contains(@id, \'{}\') and contains(text(), \'{}\')]'
            .format(
                LOCATOR_PROBING_CLASS,
                LOCATOR_PROBE_CATEGORY_SUFFIX,
                LOCATOR_PROBE_RUNNING_TEXT)):
            return True
    except NoSuchElementException:
        return False


def submit_website_test_form(selenium, domain):
    selenium.get(BASE_URL)
    website_test_url_input = selenium.find_element_by_id(LOCATOR_WEBSITE_TEST_FORM_ID)
    website_test_url_input.clear()
    website_test_url_input.send_keys(domain)
    website_test_url_input.submit()


def wait_for_test_to_start(selenium, domain):
    # Wait for the test to start or the result page to show
    # Both have the same HTML title
    WebDriverWait(selenium, 30).until(
        EC.title_contains('{}{}'.format(LOCATOR_PROGRESS_AND_RESULT_TITLE_PREFIX, domain)))


# Will raise TimeoutException on failure
def wait_for_test_to_complete(selenium):
    while not results_overview_is_present(selenium) and probes_are_running(selenium):
        time.sleep(1)

    # We should see the result page soon...
    # This will throw a TimeoutException if the element isn't
    # found within the time period specified.
    WebDriverWait(selenium, 30).until(
        EC.presence_of_element_located((By.ID, LOCATOR_RESULTS_OVERVIEW_ID)))


class DomainConfig:
    def __init__(self, domain, expected_failures):
        self.domain = domain
        self.expected_failures = tuple(ALWAYS_EXPECTED_FAILURES) + tuple(expected_failures)


def id_generator(val):
    if isinstance(val, DomainConfig):
        return val.domain.split('.')[0]


websites_to_test = [
    DomainConfig('tls1213.test.nlnetlabs.nl', []),
    # DomainConfig('tls1213ipv4only.test.nlnetlabs.nl', [TEST_IPV6_ADDRESS_FOR_WEB_SERVER]),
    # DomainConfig('tls1213wrongcertname.test.nlnetlabs.nl', [TEST_DOMAIN_NAME_ON_CERT]),
    # DomainConfig('tls1213sni.test.nlnetlabs.nl', []),
    # DomainConfig('tls1213nohsts.test.nlnetlabs.nl', [TEST_HSTS]),
    # DomainConfig('tls1213shorthsts.test.nlnetlabs.nl', [TEST_HSTS]),
    # DomainConfig('nossl.test.nlnetlabs.nl', [TEST_HTTPS_AVAILABLE]),
    # DomainConfig('tls11only.test.nlnetlabs.nl', []),
    # DomainConfig('tls12only.test.nlnetlabs.nl', []),
    pytest.param(DomainConfig('tls13only.test.nlnetlabs.nl', []), marks=pytest.mark.xfail(reason='not yet supported'))
]


@pytest.mark.parametrize('config', websites_to_test, ids=id_generator)
def test_websites(request, selenium, config):
    submit_website_test_form(selenium, config.domain)
    wait_for_test_to_start(selenium, config.domain)
    wait_for_test_to_complete(selenium)
    assert not get_failed_tests(request.node.name, selenium, config.expected_failures)
