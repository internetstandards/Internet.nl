import subprocess


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
