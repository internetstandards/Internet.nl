# this tests if a task can be executed using gevent, eventlet, and to see if tasks with an unbound context also function
# This due to hanging tasks
import os

import pytest

from internetnl import log
from internetnl.celery import dummy_task
import time
from checks.tasks.ipv6 import web


def wait_for_result(task_id):
    """Wait for all (sub)tasks to complete and return result."""
    # wait for all tasks to be completed
    while not task_id.ready():
        # show intermediate status
        log.debug("Task execution status: %s", task_id.state)
        time.sleep(1)

    # return final results, don't reraise exceptions
    result = task_id.get(propagate=False)
    task_id.forget()
    return result


# @pytest.mark.skipif(os.getenv("GITHUB_ACTIONS", "") == "True", reason="Redis hang? at github actions")
@pytest.mark.skip
def test_various_workers(custom_celery_worker):
    """Simple test that starts a task on all different worker-types (gevent, prefork, eventlet) to
    verify that operations are normal. This requires a redis server to be reachable on the configured port in
    settings.py."""

    log.debug("Applying task async")
    task_id = dummy_task.si(2).apply_async()
    result = wait_for_result(task_id)
    assert result == 4


# @pytest.mark.skipif(os.getenv("GITHUB_ACTIONS", "") == "True", reason="Redis hang? at github actions")
@pytest.mark.skip
def test_task_with_unbound_context(custom_celery_worker):
    """Verify a task can be started with unbound context. The unbound context works fine in prefork,
    but does it also function well in gevent and eventlet situations. We'll find out.

    Note: this will not lead to more test coverage as there the execution of this code happens somewhere else.
    """
    # Todo: test if there is a connection with a fixture.

    task = web.si("internet.nl").apply_async()
    result = wait_for_result(task)

    """
    This is a live test, so it needs an internet connection.
    The score will vary, but there will be a result with the domain name in there, regardless of the measurement.
    (
         'web',
         {'domains': [{'domain': 'internet.nl',
                       'score': 0,
                       'v4_bad': [],
                       'v4_good': [],
                       'v6_bad': [],
                       'v6_conn_diff': [],
                       'v6_good': []}],
          'score': 0,
          'simhash_distance': 110,
          'simhash_score': 0},
        )

    """

    _, measurement = result
    assert measurement["domains"][0]["domain"] == "internet.nl"


def test_gunicorn_webserver():
    # test if the application starts with a gunicorn server and if there is a front page.
    # In the future we want to be able to start a test via the frontpage and see that happen on eventlet.
    ...
