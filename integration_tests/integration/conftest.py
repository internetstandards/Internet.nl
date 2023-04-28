import pytest
import subprocess
import time

@pytest.fixture(scope="session")
def unique_id():
    """Generate a unique (enough) ID so multiple test instances running at the same time don't conflict on resources (eg: Docker network/compose project name, etc)"""
    return str(int(time.time()))

#
# @pytest.fixture(autouse=True, scope="session")
# def validate_environment(pytestconfig):
#     command = f'docker compose --ansi=never --env-file "test.env" --project-name "internetnl-test" exec worker ping --count=1 --timeout=1 1.1.1.1'
#     try:
#         subprocess.check_output(command, shell=True, universal_newlines=True)
#     except subprocess.CalledProcessError:
#         # we expect you to die mister bond
#         pass
#     else:
#         pytest.fail("Precondition failed: test environment not properly isolated, worker can connect to internet.")
#
#     command = f'docker compose --ansi=never --env-file "test.env" --project-name "internetnl-test" exec worker dig example.com +tries=1 +time=3'
#     try:
#         subprocess.check_output(command, shell=True, universal_newlines=True)
#     except subprocess.CalledProcessError:
#         # we expect you to die mister bond
#         pass
#     else:
#         pytest.fail("Precondition failed: test environment not properly isolated, worker can resolve external DNS records.")
