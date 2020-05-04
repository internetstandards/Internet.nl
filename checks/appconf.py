# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
import json

from django.apps import AppConfig
from django_redis import get_redis_connection
from django.conf import settings
from django.core.cache import cache

from checks import redis_id


def load_padded_macs_in_cache():
    """
    Load the padded macs in cache for faster testing.

    """
    try:
        red = get_redis_connection()
        with open(settings.PADDED_MACS) as f:
            red.hmset(redis_id.padded_macs.id, json.load(f))
    except Exception:
        pass


def clear_cached_pages():
    """
    Clear all previously cached pages.

    """
    pattern = redis_id.simple_cache_page.id.split(':', 1)[0]
    cache.delete_pattern("{}*".format(pattern))


def cache_report_metadata():
    """
    Store the report metadata used in the batch API.

    """
    if settings.ENABLE_BATCH:
        from checks.batch.util import ReportMetadata
        metadata = ReportMetadata().build_report_metadata()
        cache_id = redis_id.batch_metadata.id
        cache.set(cache_id, metadata['name_map'])
        del metadata['name_map']

        cache_id = redis_id.report_metadata.id
        cache.set(cache_id, metadata)


class ChecksAppConfig(AppConfig):
    name = 'checks'

    def ready(self):
        load_padded_macs_in_cache()
        clear_cached_pages()
        cache_report_metadata()
