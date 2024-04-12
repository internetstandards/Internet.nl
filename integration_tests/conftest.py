import pytest
import time
import subprocess
import os

# primary URL for internet.nl test website
APP_DOMAIN = "internet.test"

APP_URL = f"https://{APP_DOMAIN}"
INTEGRATIONTEST_APP_URL = "http://localhost:8081"

# additional subdomains that serve the test website
APP_URL_SUBDOMAINS = [
    APP_URL,
    "https://en.internet.test",
    "https://nl.internet.test",
    "https://www.internet.test",
    "https://ipv6.internet.test",
]

# domain used for the test target web server
TEST_DOMAIN = "target.test"

# domain used for the test target email server
TEST_EMAIL = "mail-target.test"

# exclude lines matching this grep extended regex so debug logging is not so crowded
REGEX_LOGGING_EXCLUDE = "GET /static"

COMPOSE_PROJECT_NAME = os.environ.get("COMPOSE_PROJECT_NAME")


@pytest.fixture(scope="session")
def browser_context_args(browser_context_args):
    """Overwrite default context to ignore TLS errors."""
    return {**browser_context_args, "ignore_https_errors": True}


@pytest.fixture
def page(context):
    """Overwrite default page to add logging of console messages and requests."""
    page = context.new_page()
    page.on("console", lambda msg: print(f"Console message: {msg.text}, type: {msg.type}"))
    page.on("requestfinished", lambda request: print(f"Request: {request.url}, status: {request.response().status}"))
    yield page


@pytest.fixture(scope="session")
def app_url(request):
    return APP_URL


@pytest.fixture(scope="session")
def app_domain():
    return APP_DOMAIN


@pytest.fixture(scope="session", params=APP_URL_SUBDOMAINS)
def app_url_subdomain(request):
    return request.param


@pytest.fixture(scope="function")
def test_domain(unique_id):
    return f"{unique_id}.{TEST_DOMAIN}"


@pytest.fixture(scope="function")
def test_email(unique_id):
    return f"{unique_id}.{TEST_EMAIL}"


@pytest.fixture(scope="function")
def unique_id():
    """Generate a unique (enough) ID so multiple test instances running at the same time don't
    conflict on resources (eg: Docker network/compose project name, etc)"""
    return str(int(time.time()))


@pytest.fixture(autouse=True, scope="session")
def docker_compose_logs():
    """This fixture is automatically added to each test. It will capture most relevant logs from
    Docker containers during the test run and print them so they may be presented on test failure."""

    # tail the container logs for application container and webserver, and output to stdout to have Pytest capture it
    command = (
        "docker compose --ansi=never --project-name={COMPOSE_PROJECT_NAME}"
        " logs --follow --tail=0 app worker beat resolver webserver"
        f"| grep --extended-regexp --invert-match '{REGEX_LOGGING_EXCLUDE}'"
    )
    process = subprocess.Popen(command, shell=True, universal_newlines=True)

    yield process

    process.terminate()


def print_results_url(page):
    print(f"\nResults page url: {page.url.replace(APP_URL,  INTEGRATIONTEST_APP_URL)}")


@pytest.fixture(scope="session")
def docker_compose_command():
    """Execute specific compose command"""

    yield lambda command: subprocess.check_output(
        f"docker compose --ansi=never --project-name={COMPOSE_PROJECT_NAME} {command}", shell=True
    )


@pytest.fixture(scope="session")
def docker_compose_exec():
    """Execute specific command in a service container"""

    yield lambda service, command: subprocess.check_output(
        f"docker compose --ansi=never --project-name={COMPOSE_PROJECT_NAME} exec {service} {command}", shell=True
    )


@pytest.fixture(scope="session")
def trigger_cron(docker_compose_exec):
    """Trigger specific cron job manually"""

    yield lambda cron, service="cron": docker_compose_exec(service, f"/etc/periodic/{cron}")


@pytest.fixture(scope="session")
def trigger_scheduled_task(docker_compose_exec):
    """Run specific celery beat task"""

    def _trigger_scheduled_task(beat_task):
        command = (
            "from internetnl.celery import app;"
            f'task = app.signature(app.conf.beat_schedule["{beat_task}"]["task"]);'
            "task.apply_async().get();"
        ).replace("\n", "")
        docker_compose_exec("beat", f"./manage.py shell --command='{command}'")

    yield _trigger_scheduled_task


@pytest.fixture(scope="function")
def clear_webserver_cache(docker_compose_exec):
    docker_compose_exec("webserver", "find /var/tmp/nginx_cache -delete")


def print_details_test_results(page):
    """Print detail test results from the result page for debugging failed tests."""
    try:
        # for debugging failed tests
        for section in page.locator("section.test-header").all():
            section.get_by_role("button", name="Show details").click()
        for section in page.locator("section.testresults").all():
            print(section.inner_text())
    except Exception:
        # don't fail the test if we somehow failed to get the test result details debug information
        print("Failed to gather detailed test results.")


def pytest_report_header(config):
    try:
        docker_version = subprocess.check_output(
            "docker version --format '{{.Server.Version}} {{.Server.Os}}/{{.Server.Arch}}'",
            shell=True,
            universal_newlines=True,
        ).strip()
    except Exception:
        docker_version = "n/a"

    try:
        docker_compose_version = subprocess.check_output(
            "    docker compose version --short", shell=True, universal_newlines=True
        ).strip()
    except Exception:
        docker_compose_version = "n/a"

    return [
        f"docker_version: {docker_version}",
        f"docker_compose_version: {docker_compose_version}",
    ]


def print_red(*args):
    """Color things red to make them stand out more in test output."""
    print("\033[91m", end=None)
    print(*args)
    print("\033[0m", end=None)
