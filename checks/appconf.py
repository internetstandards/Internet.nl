# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
import json

from django.apps import AppConfig
from django_redis import get_redis_connection
from django.conf import settings
from django.core.cache import cache

from checks import redis_id


def _load_padded_macs_in_cache():
    """
    Loads the padded macs in cache for faster testing.

    """
    try:
        red = get_redis_connection()
        with open(settings.PADDED_MACS) as f:
            red.hmset(redis_id.padded_macs.id, json.load(f))
    except Exception:
        pass


def _clear_cached_pages():
    """
    Clears all previously cached pages.

    """
    pattern = redis_id.simple_cache_page.id.split(':', 1)[0]
    cache.delete_pattern("{}*".format(pattern))


def _batch_startup_checks():
    if settings.ENABLE_BATCH:
        from checks.batch.util import APIMetadata
        from checks.batch.custom_results import CUSTOM_RESULTS_MAP

        def cache_report_metadata():
            """
            Stores the report metadata used in the batch API.

            """
            APIMetadata.build_metadata()

        def check_custom_results_names():
            """
            Checks that names used for the custom results do not conflict with
            existing names and configured values are correct.

            """
            for result_name in settings.BATCH_API_CUSTOM_RESULTS:
                if result_name not in CUSTOM_RESULTS_MAP:
                    raise ValueError(
                        f"Unknown configured custom result ({result_name}).")

            metadata = APIMetadata.get_report_metadata()['data']
            for name, r in CUSTOM_RESULTS_MAP.items():
                if r.name in metadata:
                    raise ValueError(
                        f"Custom result ({name}) has a conflicting name "
                        f"({r.name}) with an existing report item.")

        cache_report_metadata()
        check_custom_results_names()


class ChecksAppConfig(AppConfig):
    name = 'checks'

    def ready(self):
        pass
        _load_padded_macs_in_cache()
        _clear_cached_pages()
        _batch_startup_checks()
