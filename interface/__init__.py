# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
import mimetypes
from functools import wraps

from celery import shared_task
from django.conf import settings
from django.core.cache import cache

from interface import redis_id

mimetypes.add_type("text/x-component", ".htc")


def dummy_wrapper(*args, **kwargs):
    """
    Custom dummy wrapper.

    """

    def dummy_function(*args, **kwargs):
        return

    return dummy_function


# Do not register the batch tasks when batch is not enabled. Because... why?
batch_shared_task = shared_task  # if settings.ENABLE_BATCH else dummy_wrapper


def simple_cache_page(function):
    """
    Custom decorator for caching pages.
    Simple caching with the full request path and the batch username if any.

    """
    cache_id_name = redis_id.simple_cache_page.id
    cache_ttl = redis_id.simple_cache_page.ttl

    @wraps(function)
    def wrap(request, *args, **kwargs):
        username = "None"
        batch_user = kwargs.get("batch_user")
        if batch_user:
            username = batch_user.username
        cache_id = cache_id_name.format(username, request.current_language_code, request.get_full_path())
        response = cache.get(cache_id)
        if response:
            return response
        response = function(request, *args, **kwargs)
        cache.set(cache_id, response, timeout=cache_ttl)
        return response

    return wrap
