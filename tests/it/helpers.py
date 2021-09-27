# TODO: Use Selenium Page Objects
import copy
import re
import time
from selenium.webdriver.common.by import By
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC


BASE_URL = 'http://{0}.internetnl.test.nlnetlabs.tk:8080/'
IMPERFECT_SCORE = 'IMPERFECT'
PERFECT_SCORE = '100%'
INSUFFICIENT_TEXT = 'insufficient'
PHASE_OUT_TEXT = 'phase out'
PHASE_OUT_TEXT_NL = 'uit te faseren'
NOTTESTABLE_TEXT = 'not testable'
NOTREACHABLE_TEXT = 'not reachable'
ANY = None

LOCATOR_REPORT_SHOW_DETAILS_BUTTON_CLASS = 'panel-button-show'
LOCATOR_WARNING_TEST_CLASS = 'testresult warning'
LOCATOR_INFO_TEST_CLASS = 'testresult info'
LOCATOR_FAILED_TEST_CLASS = 'testresult failed'
LOCATOR_NOTTESTED_TEST_CLASS = 'testresult not-tested'
LOCATOR_ERROR_TEST_CLASS = 'testresult error'
LOCATOR_GOOD_NOTTESTED_TEST_CLASS = 'testresult good-not-tested'
LOCATOR_PASSED_TEST_CLASS = 'testresult passed'

LOCATOR_PROBING_CLASS = 'probing'
LOCATOR_PROBE_CATEGORY_SUFFIX = '-summary'
LOCATOR_PROBE_RUNNING_TEXT = 'Running...'
LOCATOR_WEBSITE_TEST_INPUT_ID = 'web-url'
LOCATOR_MAIL_TEST_INPUT_ID = 'mail-url'
LOCATOR_RESULTS_OVERVIEW_ID = 'testresults-overview'
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
    DANE_ROLLOVER_SCHEME = 'DANE rollover scheme'
    DKIM_EXISTS = 'DKIM existence'
    DMARC_EXISTS = 'DMARC existence'
    SPF_EXISTS = 'SPF existence'
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
    TLS_CIPHER_SUITES = 'Ciphers (Algorithm selections)'
    TLS_CIPHER_ORDER = 'Cipher order'
    TLS_CLIENT_RENEG = 'Client-initiated renegotiation'
    TLS_COMPRESSION = 'TLS compression'
    TLS_KEY_EXCHANGE = 'Key exchange parameters'
    TLS_KEY_EXCHANGE_NL = 'Sleuteluitwisselingsparameters'
    TLS_OCSP_STAPLING = 'OCSP stapling'
    TLS_SECURE_RENEG = 'Secure renegotiation'
    TLS_VERSION = 'TLS version'
    TLS_VERSION_NL = 'TLS-versie'
    TLS_ZERO_RTT = '0-RTT'
    TLS_ZERO_RTT_NL = '0-RTT'
    TLS_HASH_FUNC = 'Hash function for key exchange'
    TLS_HASH_FUNC_NL = 'Hashfunctie voor sleuteluitwisseling'
    STARTTLS_AVAILABLE = 'STARTTLS available'
    IPV6_NS_ADDRESS = 'IPv6 addresses for name servers'
    IPV6_NS_REACHABILITY = 'IPv6 reachability of name servers'
    IPV6_WEB_ADDRESS = 'IPv6 addresses for web server'
    IPV6_MAIL_ADDRESS = 'IPv6 addresses for mail server(s)'
    IPV6_WEB_REACHABILITY = 'IPv6 reachability of web server'
    IPV6_MAIL_REACHABILITY = 'IPv6 reachability of mail server(s)'
    IPV6_WEB_SAME_WEBSITE = 'Same website on IPv6 and IPv4'
    SECURITY_HTTP_XFRAME = 'X-Frame-Options'
    SECURITY_HTTP_XCONTYPE = 'X-Content-Type-Options'
    SECURITY_HTTP_CSP = 'Content-Security-Policy'
    SECURITY_HTTP_REFERRER = 'Referrer-Policy existence'


class UX:
    @staticmethod
    def _get_test_names(testresult_anchors):
        test_titles = set()
        for test_title_anchor in testresult_anchors:
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
            # node as sometimes that isn't TEST TITLE but instead is 'open' (or
            # 'close', or 'sluit' in Dutch). Strip off the success or failure
            # status text (e.g. 'Failed:', 'Niet-testbaar:', etc) and the
            # span open/close text, hopefully we are left with just the test
            # title. This would be easier if each test report block had a
            # language independent unique test idenfitier we could extract
            # instead of a language dependent title plus nearby markup...
            test_title = re.sub(r'(open|close|sluit|[A-Za-z-, ]+:)', '',
                test_title_anchor.text).strip()
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
    def get_info_tests(selenium):
        return UX._get_matching_tests(selenium, LOCATOR_INFO_TEST_CLASS)

    @staticmethod
    def get_nottested_tests(selenium):
        return (UX._get_matching_tests(selenium, LOCATOR_NOTTESTED_TEST_CLASS) |
                UX._get_matching_tests(selenium, LOCATOR_GOOD_NOTTESTED_TEST_CLASS))

    @staticmethod
    def get_error_tests(selenium):
        return UX._get_matching_tests(selenium, LOCATOR_ERROR_TEST_CLASS)

    @staticmethod
    def get_passed_tests(selenium):
        return UX._get_matching_tests(selenium, LOCATOR_PASSED_TEST_CLASS)

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
    def submit_website_test_form(selenium, domain, lang='en', mail=False, base_url=None):
        base_url = base_url or BASE_URL
        selenium.get(base_url.format(lang))
        if mail:
            website_test_url_input = selenium.find_element_by_id(
                LOCATOR_MAIL_TEST_INPUT_ID)
        else:
            website_test_url_input = selenium.find_element_by_id(
                LOCATOR_WEBSITE_TEST_INPUT_ID)
        website_test_url_input.clear()
        website_test_url_input.send_keys(domain)
        website_test_url_input.submit()

    @staticmethod
    def wait_for_test_to_start(selenium, domain):
        # Wait for the test to start or the result page to show
        # Both contain the domain under test in the HTML page title
        WebDriverWait(selenium, 10).until(
            EC.title_contains('{}'.format(domain)))

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
        WebDriverWait(selenium, 180).until(
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
                 expected_failures=None,
                 expected_warnings=None,
                 expected_info=None,
                 expected_not_tested=None,
                 expected_error=None,
                 expected_passes=None,
                 expected_score=None):
        self.test_id = test_id
        self.domain = domain
        self.expected_failures = self.clone_as_dict(expected_failures)
        self.expected_warnings = self.clone_as_dict(expected_warnings)
        self.expected_info = self.clone_as_dict(expected_info)
        self.expected_not_tested = self.clone_as_dict(expected_not_tested)
        self.expected_error = self.clone_as_dict(expected_error)
        self.expected_passes = self.clone_as_dict(expected_passes)
        self.expected_score = expected_score

        self.override_defaults()

        if not expected_score and not (self.expected_failures or self.expected_error):
            self.expected_score = PERFECT_SCORE

    @staticmethod
    def clone_as_dict(dict_or_set):
        if isinstance(dict_or_set, dict):
            return copy.deepcopy(dict_or_set)
        elif isinstance(dict_or_set, set):
            return copy.deepcopy(dict.fromkeys(dict_or_set, None))
        elif dict_or_set is None:
            return dict()
        else:
            raise ValueError()

    def override_defaults(self):
        pass


class GoodDomain(DomainConfig):
    def __init__(self, testid, domain, expected_not_tested=None):
        super().__init__(testid, domain,
            expected_not_tested=expected_not_tested,
            expected_score=PERFECT_SCORE)


class BadDomain(DomainConfig):
    def __init__(self, testid, domain, expected_failures=None):
        super().__init__(testid, domain,
            expected_failures=expected_failures,
            expected_score=IMPERFECT_SCORE)


def domainconfig_id_generator(val):
    if isinstance(val, DomainConfig):
        return '{}-{}'.format(
            val.test_id, val.domain.split('.')[0])
