# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
from celery import group
from celery.result import AsyncResult
from django.core.cache import cache
from django_redis import get_redis_connection
from django.conf import settings

from interface import redis_id
from internetnl import log


def user_limit_exceeded(req_limit_id):
    """
    Check if the user (based on HTTP remote address) is currently running more
    checks than allowed.

    """
    red = get_redis_connection("default")
    current_usage = red.scard(req_limit_id)
    red.close()
    return current_usage > settings.CLIENT_RATE_LIMIT


def check_results(url, checks_registry, remote_addr, get_results=False):
    """
    Check if results are ready for a task and return the status (True, False).
    If there are results return them also.

    If the task is not registered and the user has not passed the task limit,
    start the task.

    """
    url = url.lower()
    cache_id = redis_id.dom_task.id.format(url, checks_registry.name)
    cache_ttl = redis_id.dom_task.ttl

    task_id = cache.get(cache_id)
    while not task_id:
        log.debug("No task found for task in cache. Creating a new redis task.")
        # Task is not yet available (not running AND not in cache)
        # Limit concurrent task launches per IP
        req_limit_id = redis_id.req_limit.id.format(remote_addr)
        req_limit_ttl = redis_id.req_limit.ttl
        if user_limit_exceeded(req_limit_id):
            log.debug("User limit exceeded. Too many requests from this IP. Blocked.")
            return (False, dict(status="User limit exceeded, try again later"))
        # Try to aquire lock and start tasks
        elif cache.add(cache_id, False, cache_ttl):
            # Submit test
            log.debug("Submitting a new task set.")
            task_set = submit_task_set(url, checks_registry, req_limit_id)
            # Cache task_set
            task_id = task_set.id
            cache.set(cache_id, task_id, cache_ttl)
            # Increase running tasks per IP
            red = get_redis_connection("default")
            red.sadd(req_limit_id, task_id)
            red.expire(req_limit_id, req_limit_ttl)
            red.close()

    cache.close()
    log.debug("Trying to retrieve asyncresult from task_id: %s.", task_id)
    callback = AsyncResult(task_id)
    if callback.task_id and callback.ready():
        results = {}
        if get_results:
            gets = callback.get()
            for res in gets:
                results[res[0]] = res[1]
        return True, results
    else:
        log.debug("Task is not yet ready.")
    return False, {}


def submit_task_set(url, checks_registry, req_limit_id=None, error_cb=None):
    """
    Create the necessary celery workflow and start the task set.

    """
    # Attach an error callback if provided (mainly for batch testing).
    if error_cb:
        task_set = group(check.s(url) for check in checks_registry.all) | checks_registry.callback.s(url).on_error(
            error_cb.s()
        )
    else:
        task_set = group(check.s(url) for check in checks_registry.all) | checks_registry.callback.s(url, req_limit_id)
    if checks_registry.pre_test:
        task_set = checks_registry.pre_test.s(url) | task_set

    task_set = task_set()
    return task_set


def check_registry(name, cb, pre_test=None):
    """
    Decorator for registering the various web/mail checks.

    """
    checks = []

    def register(func):
        checks.append(func)
        return func

    register.name = name
    register.all = checks
    register.callback = cb
    register.pre_test = pre_test
    return register


def post_callback_hook(req_limit_id, task_id):
    """
    Removes the task from the user's registered tasks.

    SHOULD be always called as the last part of a task chain.

    """
    red = get_redis_connection("default")
    red.srem(req_limit_id, task_id)
    red.close()
