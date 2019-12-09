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
    None: {'missing', 'white' },
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
        cells[0] = html.th('Result', class_='sortable result initial-sort asc active', title=f'Passed if the test results for this domain in both the {reference} and {demo} instances is 100%, Failed otherwise.')
        cells[1] = html.th('Domain', class_='sortable')
        cells.insert(2, html.th('Delta Score (%)', class_='sortable numeric', title=f'The difference between the {reference} score and the {demo} score for this domain'))
        cells.insert(3, html.th('Subtest Results (hover for details)'))
        cells.insert(4, html.th('New Failures', class_='sortable'))
        cells.insert(5, html.th('New Warnings', class_='sortable'))


def br_join(iterable):
    # create [(a, br), (b, br)] from [a, b] and also handle the None case
    item_br_tuples = [(item, html.br()) for item in iterable or list()]
    # flatten [(a, br), (b, br)] to [a, br, b, br]
    joined = [item for sublist in item_br_tuples for item in sublist]
    # discard final br, if any
    joined and joined.pop()
    return joined


# ensure we have some text in the case of an empty list so that sortable JS
# doesn't fall over on the empty cell.
def sortsafe(cell_content):
    return cell_content if cell_content else 'None'


# pytest-html hook to manipulate the HTML report table rows, one test/row per
# invocation. Depends on '_score' and '_subresults' attributes being created
# by the pytest_runtest_makereport() hook below.
def pytest_html_results_table_row(report, cells):
    if hasattr(report, '_batch') and report._batch:
        score = "-0"  # unable to resovle the domain
        subresult_html = []

        if report._score:
            score = report._score[0]

            for k in sorted(report._subresults[0].keys()):
                subresult_html.append(make_result_square(k, report._subresults[0][k]))
            subresult_html.append(html.span(f'{report._reference}', style='padding-left: 5px'))

            if len(report._subresults) > 1:
                subresult_html.append(html.br())
                for k in sorted(report._subresults[0].keys()):
                    if k in report._subresults[1]:
                        result = report._subresults[1].pop(k)
                    else:
                        result = None
                    subresult_html.append(make_result_square(k, result))
                for k in sorted(report._subresults[1].keys()):
                    subresult_html.append(make_result_square(k, report._subresults[1][k]))
                subresult_html.append(html.span(f'{report._demo}', style='padding-left: 5px'))
                score = report._score[1] - score

        cells[1] = html.td(sortsafe(report._fqdn))
        cells.insert(2, html.td(sortsafe(score)))
        cells.insert(3, html.td(sortsafe(subresult_html), style='font_family:monospace'))
        cells.insert(4, html.td(sortsafe(br_join(report._failures))))
        cells.insert(5, html.td(sortsafe(br_join(report._warnings))))


def pytest_html_results_table_html(report, data):
    if hasattr(report, '_batch') and report._batch:
        # Remove the embedded screenshot preview in the result details row to
        # speed up page load time for large (batch-like) reports.
        del data[0]


# pytest hook invoked after each test. If the test added a '_score' attribute
# pass it on so that the pytest-html hooks above can access it.
@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    if hasattr(item, '_batch') and item._batch:
        report = outcome.get_result()
        report._batch = True
        report._fqdn = getattr(item, '_fqdn', None)
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
