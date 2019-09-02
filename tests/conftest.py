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
def pytest_html_results_table_header(session, cells):
    if session.config.getoption("--batch-input-file", None):
        (reference, demo) = session.config.getoption("--batch-base-names").split(',')
        cells[0] = html.th('Result', class_='sortable result initial-sort asc active' title=f'Passed if the test results for this domain in both the {reference} and {demo} instances is 100%, Failed otherwise.')
        cells[1] = html.th('Domain', class_='sortable domain', col='domain')
        cells.insert(2, html.th('Delta Score (%)', class_='sortable score numeric', col='score', title=f'The difference between the {reference} score and the {demo} score for this domain'))
        cells.insert(3, html.th('Subtest Results (hover for details)'))
        cells.insert(4, html.th('New Failures'))
        cells.insert(5, html.th('New Warnings'))


# pytest-html hook to manipulate the HTML report table rows, one test/row per
# invocation. Depends on '_score' and '_subresults' attributes being created
# by the pytest_runtest_makereport() hook below.
def pytest_html_results_table_row(report, cells):
    if hasattr(report, '_score') and report._score:
        subresult_html = []
        score = report._score[0]

        for k in sorted(report._subresults[0].keys()):
            subresult_html.append(make_result_square(k, report._subresults[0][k]))
        subresult_html.append(html.span(f'{report._reference}', style='padding-left: 5px'))

        if len(report._subresults) > 1:
            subresult_html.append(html.br())
            for k in sorted(report._subresults[0].keys()):
                result = report._subresults[1].pop(k)
                subresult_html.append(make_result_square(k, result))
            for k in sorted(report._subresults[1].keys()):
                subresult_html.append(make_result_square(k, report._subresults[1][k]))
            subresult_html.append(html.span(f'{report._demo}', style='padding-left: 5px'))
            score = report._score[1] - score

        cells[1] = html.td(report._fqdn)
        cells.insert(2, html.td(score))
        cells.insert(3, html.td(subresult_html, style='font_family:monospace'))
        cells.insert(4, html.td([html.li(item) for item in report._failures]))
        cells.insert(5, html.td([html.li(item) for item in report._warnings]))


# pytest hook invoked after each test. If the test added a '_score' attribute
# pass it on so that the pytest-html hooks above can access it.
@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    if hasattr(item, '_score'):
        report = outcome.get_result()
        report._fqdn  = getattr(item, '_fqdn', None)
        report._score = getattr(item, '_score', [0])
        report._subresults = getattr(item, '_subresults', [None])
        report._failures = getattr(item, '_failures', set())
        report._warnings = getattr(item, '_warnings', set())
        (report._reference, report._demo) = item.config.getoption("--batch-base-names").split(',')

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
        "--batch-base-urls", action="store", default=None,
        help="Comma separated base URLs of the Internet.NL instances to test"
    )
    parser.addoption(
        "--batch-base-names", action="store", default="reference,demo",
        help="Comma separated friendly names of the Internet.NL instances to test"
    )


@pytest.fixture
def batch_base_urls(request):
    return request.config.getoption("--batch-base-urls").split(',')


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
