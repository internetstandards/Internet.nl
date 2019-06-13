import time
from selenium.webdriver.common.by import By
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC


BASE_URL = 'http://internet.nl:8080/'

LOCATOR_REPORT_SHOW_DETAILS_BUTTON_CLASS = 'panel-button-show'
LOCATOR_FAILED_TEST_CLASS = 'testresult failed'
LOCATOR_PROBING_CLASS = 'probing'
LOCATOR_PROBE_CATEGORY_SUFFIX = '-summary'
LOCATOR_PROBE_RUNNING_TEXT = 'Running...'
LOCATOR_WEBSITE_TEST_FORM_ID = 'web-url'
LOCATOR_RESULTS_OVERVIEW_ID = 'testresults-overview'
LOCATOR_PROGRESS_AND_RESULT_TITLE_PREFIX = 'Website test: '

XPATH_PROBES = (
    '//*[@class=\'{}\']'
    '/span['
    'contains(@id, \'{}\') and contains(text(), \'{}\')'
    ']').format(
    LOCATOR_PROBING_CLASS,
    LOCATOR_PROBE_CATEGORY_SUFFIX,
    LOCATOR_PROBE_RUNNING_TEXT)

XPATH_FAILED_TESTS = (
    '//*[@class=\'{}\']/h3/a'
    ).format(LOCATOR_FAILED_TEST_CLASS)


class TESTS:
    CERT_TRUST = 'Trust chain of certificate'
    DOMAIN_NAME_ON_CERT = 'Domain name on certificate'
    IPV6_ADDRESS_FOR_WEB_SERVER = 'IPv6 addresses for web server'
    HSTS = 'HSTS'
    HTTPS_AVAILABLE = 'HTTPS available'
    SAME_WEBSITE_ON_IPV4_AND_IPV6 = 'Same website on IPv6 and IPv4'
    TLS_VERSION = 'TLS version'
    ZERO_RTT = '0-RTT'
    OCSP_STAPLING = 'OCSP Stapling'
    CIPHER_SUITES = 'Cipher suites'
    CLIENT_RENEG = 'Client-initiated renegotiation'


class UX:
    @staticmethod
    def get_failed_tests(selenium):
        testresult_failed_anchors = selenium.find_elements(
            By.XPATH, XPATH_FAILED_TESTS)

        failed_tests = set()
        for title_anchor_of_failed_test in testresult_failed_anchors:
            # This element should be an anchor ('<a>') child of a <div>
            # structure like so:
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
            #       <span class="icon"><img ...></span>
            #     </a>
            #   </h3>
            # We are interested in the TEST TITLE. We hope that
            # WebElement.text() contains it. The DOM elements don't always
            # appear to be in the same order so we can't just use the 2nd text
            # node as sometimes that isn't TEST TITLE but instead is 'open'.
            internetnl_test_title = title_anchor_of_failed_test.text \
                .replace("Failed:", '') \
                .replace("open", '').strip() \
                .replace("close", '').strip()
            failed_tests.add(internetnl_test_title)

        return failed_tests

    @staticmethod
    def results_overview_is_present(selenium):
        try:
            if selenium.find_element_by_id(LOCATOR_RESULTS_OVERVIEW_ID):
                return True
        except NoSuchElementException:
            return False

    @staticmethod
    def probes_are_running(selenium):
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
            return selenium.find_element_by_xpath(XPATH_PROBES)
        except NoSuchElementException:
            return False

    @staticmethod
    def submit_website_test_form(selenium, domain):
        selenium.get(BASE_URL)
        website_test_url_input = selenium.find_element_by_id(
            LOCATOR_WEBSITE_TEST_FORM_ID)
        website_test_url_input.clear()
        website_test_url_input.send_keys(domain)
        website_test_url_input.submit()

    @staticmethod
    def wait_for_test_to_start(selenium, domain):
        # Wait for the test to start or the result page to show
        # Both have the same HTML title
        WebDriverWait(selenium, 30).until(
            EC.title_contains('{}{}'.format(
                LOCATOR_PROGRESS_AND_RESULT_TITLE_PREFIX, domain)))

    # Will raise TimeoutException on failure
    @staticmethod
    def wait_for_test_to_complete(selenium):
        while (
            not UX.results_overview_is_present(selenium)
            and UX.probes_are_running(selenium)
        ):
            time.sleep(1)

        # We should see the result page soon...
        # This will throw a TimeoutException if the element isn't
        # found within the time period specified.
        WebDriverWait(selenium, 30).until(
            EC.presence_of_element_located(
                (By.ID, LOCATOR_RESULTS_OVERVIEW_ID)))

    # This is handy to do before the end of the test so that if the test fails
    # and a screenshot is made then the detail sections are open in the
    # screenshot.
    @staticmethod
    def open_report_detail_sections(selenium):
        for el in selenium.find_elements(
            By.CLASS_NAME, LOCATOR_REPORT_SHOW_DETAILS_BUTTON_CLASS
        ):
            el.click()


class DomainConfig:
    def __init__(self, domain, expected_failures={}):
        self.domain = domain
        self.expected_failures = set(expected_failures)


def id_generator(val):
    if isinstance(val, DomainConfig):
        return val.domain.split('.')[0]
