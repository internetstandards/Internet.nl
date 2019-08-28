from py.xml import html
import pytest


# -----------------------------------------------------------------------------
# BEGIN: add two custom columns to the HTML report created by pytest-html.
# -----------------------------------------------------------------------------
subresult_mappings = {
    'x': ('failed', 'red'),
    '!': ('warning', 'orange'),
    '.': ('info', 'blue'),
    '_': ('not tested', 'grey'),
    '/': ('passed', 'green'),
}


# Generate HTML and CSS to represent the given subtest result as a small
# coloured square with subtest name and status shown in a tooltip (via
# 'title').
def make_result_square(subtest_name, result):
    (status, c) = subresult_mappings[result]
    return html.div('', style=f'display:inline-block; background-color:{c}; '
        'width:5px; height:5px; margin-right:1px;',
        title=f'{status}: {subtest_name}')


# pytest-html hook to manipulate the HTML report table header
def pytest_html_results_table_header(cells):
    cells.insert(2, html.th('Score (%)', class_='sortable score numeric', col='score'))
    cells.insert(3, html.th('Subtest Results (hover for details)'))


# pytest-html hook to manipulate the HTML report table rows, one test/row per
# invocation. Depends on '_score' and '_subresults' attributes being created
# by the pytest_runtest_makereport() hook below.
def pytest_html_results_table_row(report, cells):
    if not hasattr(report, '_score'):
        cells.insert(2, html.td('-', ))
        cells.insert(3, html.td('-'))
    else:
        subresult_html = []
        for k in sorted(report._subresults.keys()):
            subresult_html.append(make_result_square(k, report._subresults[k]))
        cells.insert(2, html.td(report._score))
        cells.insert(3, html.td(subresult_html, style='font_family:monospace'))


# pytest hook invoked after each test. If the test added a '_score' attribute
# pass it on so that the pytest-html hooks above can access it.
@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    if hasattr(item, '_score'):
        report = outcome.get_result()
        report._score = getattr(item, '_score', 0)
        report._subresults = getattr(item, '_subresults', 0)
# -----------------------------------------------------------------------------
# END: add two custom columns to the HTML report created by pytest-html.
# -----------------------------------------------------------------------------


# -----------------------------------------------------------------------------
# BEGIN: configure pytest to accept batch-like related command line arguments.
# -----------------------------------------------------------------------------
# The batch-like functionality (not to be confused with Internet.NLs built-in
# batch API) uses pytest to submit a number of externally defined real website
# domains for testing by an Internet.NL deployment and captures details about
# the test results to include in an HTML report. As the integration test
# Internet.NL deployment is intended to work only with the internal fake target
# FQDNs and custom DNS hierarchy we can't submit tests for real sites on the
# internet to this deployment. Instead run the tests via the integration test
# Firefox instances so that we can capture screenshots of the test results, but
# direct Firefox to interact with the external deployment of Internet.NL, not
# the integration test deployment of Internet.NL).
# -----------------------------------------------------------------------------
def pytest_addoption(parser):
    parser.addoption(
        "--batch-input-file", action="store", default=None,
        help="path to a text file containing one domain per line"
    )
    parser.addoption(
        "--batch-base-url", action="store", default=None,
        help="Base URL of the Internet.NL instance to test"
    )


@pytest.fixture
def batch_base_url(request):
    return request.config.getoption("--batch-base-url")


# helper method used by pytest_generate_tests() below.
# returns a list of website domains to test.
def load_batch_domains(batch_input_file):
    try:
        if batch_input_file:
            print(f"Loading batch domains from file '{batch_input_file}'")
            with open(batch_input_file) as f:
                return [line.strip() for line in f.readlines()]
    except FileNotFoundError:
        pass

    return []


# When the --batch-input-file command line argument is passed to pytest load
# the file and 'parametrize' the 'batch_domain' fixture such that any test that
# uses the fixture is invoked N times each time with the next line from the
# file.
def pytest_generate_tests(metafunc):
    if "batch_domain" in metafunc.fixturenames:
        batch_domains = load_batch_domains(
            metafunc.config.getoption("--batch-input-file"))
        metafunc.parametrize("batch_domain", batch_domains)
# -----------------------------------------------------------------------------
# END: configure pytest to accept batch-like related command line arguments.
# -----------------------------------------------------------------------------
