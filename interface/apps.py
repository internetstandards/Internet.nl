# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
import json
import logging

from django.apps import AppConfig
from django.conf import settings
from django.core.cache import cache
from django.db import OperationalError, connection, utils
from django_redis import get_redis_connection

from interface import redis_id
from internetnl import log

logger = logging.getLogger(__name__)


def _load_autoconf_in_cache():
    """
    Loads any autoconf option in cache to avoid repeated DB access.

    """
    log.debug("Loading autoconf into redis cache.")
    from checks.models import AutoConf, AutoConfOption

    try:
        for option in (AutoConfOption.DATED_REPORT_ID_THRESHOLD_WEB, AutoConfOption.DATED_REPORT_ID_THRESHOLD_MAIL):
            cache_id = redis_id.autoconf.id.format(option.value)
            cache_ttl = redis_id.autoconf.ttl
            value = AutoConf.get_option(option)
            if value:
                value = int(value)
            cache.set(cache_id, value, cache_ttl)
    except (utils.ProgrammingError, OperationalError):
        # Avoid the chicken-egg problem when trying to migrate(start the app)
        # when the table is not there yet.
        pass


def _load_padded_macs_in_cache():
    """
    Loads the padded macs in cache for faster testing.

    """
    red = get_redis_connection()
    with open(settings.PADDED_MACS) as f:
        red.hmset(redis_id.padded_macs.id, json.load(f))
    red.close()


def _clear_cached_pages():
    """
    Clears all previously cached pages.

    """
    pattern = redis_id.simple_cache_page.id.split(":", 1)[0]
    cache.delete_pattern("{}*".format(pattern))


def _batch_startup_checks():
    if settings.ENABLE_BATCH:
        log.debug("Performing batch startup checks.")
        from interface.batch import BATCH_INDEXES
        from interface.batch.custom_results import CUSTOM_RESULTS_MAP
        from interface.batch.util import APIMetadata

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
                    raise ValueError(f"Unknown configured custom result ({result_name}).")

            metadata = APIMetadata.get_report_metadata()["data"]
            for name, r in CUSTOM_RESULTS_MAP.items():
                if r.name in metadata:
                    raise ValueError(
                        f"Custom result ({name}) has a conflicting name " f"({r.name}) with an existing report item."
                    )

        def check_indexes_in_place():
            """
            Checks that indexes are in place when batch is activated and
            prompts the user.

            """

            # Only perform this check when running on oracle (as intended)
            # Do not run these checks on sqlite while developing
            if "lite" in settings.DATABASES["default"]["ENGINE"]:
                log.warning(
                    "You are running the batch service on a sqlite database without proper indexes."
                    "Only do this during development. Otherwise run Oracle and apply the indexes if "
                    "a startup warning shows."
                )
                return True

            for table, index_field, index_name in BATCH_INDEXES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        f"""
SELECT
    FROM   pg_class c
    JOIN   pg_namespace n ON n.oid = c.relnamespace
    JOIN   pg_index i on c.oid = i.indexrelid
    WHERE  c.relname = '{index_name}'"""
                    )
                    res = cursor.fetchall()
                    if len(res) == 0:
                        logger.warning(
                            "ENABLE_BATCH is set for this server but the "
                            "database is lacking the required indexes. "
                            "Consider running "
                            "`manage.py api_create_db_indexes`."
                        )
                        break
                    elif len(res) > 1:
                        logger.warning(
                            "Something seemws wrong with the database "
                            "as more than one results are returned for the "
                            f"'{index_name}' index."
                        )

        cache_report_metadata()
        check_custom_results_names()
        check_indexes_in_place()


class InterfaceConfig(AppConfig):
    name = "interface"

    def ready(self):
        log.debug("Running interface startup checks.")
        _load_autoconf_in_cache()
        _load_padded_macs_in_cache()
        _clear_cached_pages()
        _batch_startup_checks()
        connection.inc_thread_sharing()
