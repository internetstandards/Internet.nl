# TODO: Use Selenium Page Objects
import copy
import re
import time
from selenium.webdriver.common.by import By
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC


BASE_URL = 'http://internet.nl:8080/'

LOCATOR_REPORT_SHOW_DETAILS_BUTTON_CLASS = 'panel-button-show'
LOCATOR_PASSED_TEST_CLASS = 'testresult passed'
LOCATOR_WARNING_TEST_CLASS = 'testresult warning'
LOCATOR_FAILED_TEST_CLASS = 'testresult failed'
LOCATOR_NOTTESTED_TEST_CLASS = 'testresult not-tested'

LOCATOR_PROBING_CLASS = 'probing'
LOCATOR_PROBE_CATEGORY_SUFFIX = '-summary'
LOCATOR_PROBE_RUNNING_TEXT = 'Running...'
LOCATOR_WEBSITE_TEST_FORM_ID = 'web-url'
LOCATOR_RESULTS_OVERVIEW_ID = 'testresults-overview'
LOCATOR_PROGRESS_AND_RESULT_TITLE_PREFIX = 'Website test: '
LOCATOR_SCORE = 'score'

XPATH_PROBES = (
    '//*[@class=\'{}\']'
    '/span['
    'contains(@id, \'{}\') and contains(text(), \'{}\')'
    ']').format(
    LOCATOR_PROBING_CLASS,
    LOCATOR_PROBE_CATEGORY_SUFFIX,
    LOCATOR_PROBE_RUNNING_TEXT)
XPATH_TEST_TITLE = '//div[@class=\'{}\']/h3/a'
XPATH_TEST_DETAILS_TABLE_BODY_ROWS = (
    '//div['
    'contains(@class,\'testresult\') and '
    'h3/a[text()[contains(.,\'{}\')]]'
    ']'
    '//div[@class=\'tech-details-table\']/table/tbody/tr'
)


class TESTS:
    DANE_EXISTS = 'DANE existence'
    DANE_VALID = 'DANE validity'
    DNSSEC_EXIST = 'DNSSEC existence'
    DNSSEC_VALID = 'DNSSEC validity'
    HTTPS_CERT_DOMAIN = 'Domain name on certificate'
    HTTPS_CERT_PUBKEY = 'Public key of certificate'
    HTTPS_CERT_SIG = 'Signature of certificate'
    HTTPS_CERT_TRUST = 'Trust chain of certificate'
    HTTPS_HTTP_COMPRESSION = 'HTTP compression'
    HTTPS_HTTP_HSTS = 'HSTS'
    HTTPS_HTTP_HTTPS_AVAILABLE = 'HTTPS available'
    HTTPS_HTTP_REDIRECT = 'HTTPS redirect'
    HTTPS_TLS_CIPHER_SUITES = 'Cipher suites'
    HTTPS_TLS_CLIENT_RENEG = 'Client-initiated renegotiation'
    HTTPS_TLS_COMPRESSION = 'TLS compression'
    HTTPS_TLS_KEY_EXCHANGE = 'Key exchange parameters'
    HTTPS_TLS_OCSP_STAPLING = 'OCSP Stapling'
    HTTPS_TLS_SECURE_RENEG = 'Secure renegotiation'
    HTTPS_TLS_VERSION = 'TLS version'
    HTTPS_TLS_ZERO_RTT = '0-RTT'
    IPV6_NS_ADDRESS = 'IPv6 addresses for name servers'
    IPV6_NS_REACHABILITY = 'IPv6 reachability of name servers'
    IPV6_WEB_ADDRESS = 'IPv6 addresses for web server'
    IPV6_WEB_REACHABILITY = 'IPv6 reachability of web server'
    IPV6_WEB_SAME_WEBSITE = 'Same website on IPv6 and IPv4'
    SECURITY_HTTP_XFRAME = 'X-Frame-Options'
    SECURITY_HTTP_XCONTYPE = 'X-Content-Type-Options'
    SECURITY_HTTP_XXSS = 'X-XSS-Protection'
    SECURITY_HTTP_CSP = 'Content-Security-Policy existence'
    SECURITY_HTTP_REFERRER = 'Referrer-Policy existence'


class UX:
    @staticmethod
    def _get_test_names(testresult_anchors):
        test_titles = set()
        for title_anchor_of_failed_test in testresult_anchors:
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
            test_title = re.sub(r'(open|close|[A-Za-z ]+:)', '',
                title_anchor_of_failed_test.text).strip()
            test_titles.add(test_title)

        return test_titles

    @staticmethod
    def _get_matching_tests(selenium, test_class):
        testresult_anchors = selenium.find_elements(
            By.XPATH, XPATH_TEST_TITLE.format(test_class))
        return UX._get_test_names(testresult_anchors)

    @staticmethod
    def get_failed_tests(selenium):
        return UX._get_matching_tests(selenium, LOCATOR_FAILED_TEST_CLASS)

    @staticmethod
    def get_warning_tests(selenium):
        return UX._get_matching_tests(selenium, LOCATOR_WARNING_TEST_CLASS)

    @staticmethod
    def get_nottested_tests(selenium):
        return UX._get_matching_tests(selenium, LOCATOR_NOTTESTED_TEST_CLASS)

    @staticmethod
    def get_score(selenium):
        return selenium.find_element(By.CLASS_NAME, LOCATOR_SCORE).text

    @staticmethod
    def get_test_detail_table_rows(selenium, test_title):
        xpath = XPATH_TEST_DETAILS_TABLE_BODY_ROWS.format(test_title)
        return selenium.find_elements_by_xpath(xpath)

    @staticmethod
    def get_table_values(selenium, test_title):
        rows = []
        for tr in UX.get_test_detail_table_rows(selenium, test_title):
            cells = []
            for td in tr.find_elements_by_tag_name('td')[1:]:
                cells.append(td.text.strip())
            rows.append(cells)
        return rows

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
    def __init__(self,
                 test_id,
                 domain,
                 expected_failures=dict(),
                 expected_warnings=dict(),
                 expected_not_tested=dict(),
                 expected_score=None):
        self.test_id = test_id
        self.domain = domain
        self.expected_failures = self.get_as_dict(expected_failures)
        self.expected_warnings = self.get_as_dict(expected_warnings)
        self.expected_not_tested = self.get_as_dict(expected_not_tested)
        self.expected_score = expected_score
        self.override_defaults()

    def get_as_dict(self, dict_or_set):
        if isinstance(dict_or_set, dict):
            return copy.deepcopy(dict_or_set)
        elif isinstance(dict_or_set, set):
            return copy.deepcopy(dict.fromkeys(dict_or_set, None))
        else:
            raise ValueError()

    def override_defaults(self):
        pass


class GoodDomain(DomainConfig):
    def __init__(self, testid, domain, not_tested=dict()):
        super().__init__(testid, domain, expected_not_tested=not_tested,
            expected_score='100%')


class BadDomain(DomainConfig):
    def __init__(self, testid, domain, failures=dict()):
        super().__init__(testid, domain, expected_failures=failures)


def id_generator(val):
    if isinstance(val, DomainConfig):
        return '{}-{}'.format(
            val.test_id, val.domain.split('.')[0])
