# this tests if a task can be executed using gevent, eventlet, and to see if tasks with an unbound context also function
# This due to hanging tasks
# import os


from internetnl import log
from internetnl.celery import dummy_task
import time


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
# @pytest.mark.skip
def test_various_workers(custom_celery_worker):
    """Simple test that starts a task on all different worker-types (gevent, prefork, eventlet) to
    verify that operations are normal. This requires a redis server to be reachable on the configured port in
    settings.py."""

    log.debug("Applying task async")
    task_id = dummy_task.si(2).apply_async()
    result = wait_for_result(task_id)
    assert result == 4
