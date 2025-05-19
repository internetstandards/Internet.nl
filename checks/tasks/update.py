# Copyright: 2022, ECP, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
from celery import shared_task
from celery.utils.log import get_task_logger
from django.core.cache import cache
from django.db import transaction

from checks.models import Fame
from interface import redis_id
from interface.batch import util

logger = get_task_logger(__name__)


class HOFEntry:
    def __init__(self, domain):
        self.domain = domain
        self.web_timestamp = None
        self.web_permalink = None
        self.mail_timestamp = None
        self.mail_permalink = None

    def __str__(self):
        return f"""------- {self.domain}
        web_timestamp: {self.web_timestamp}
        web_permalink: {self.web_permalink}
        mail_timestamp: {self.mail_timestamp}
        mail_permalink: {self.mail_permalink}
        """


@transaction.atomic
def _update_hof():
    """
    Populate the Hall of Fame with domains that scored 100% in the website
    and/or the mail test.

    .. note:: Domains that are part of the HoF are domains that their *latest*
              test scored 100%.

    """
    champions = []
    web = []
    mail = []

    for entry in Fame.objects.all().iterator():
        if entry.site_report_id is not None:
            web.append(
                {
                    "permalink": f"/site/{entry.domain}/{entry.site_report_id}/",
                    "domain": entry.domain,
                    "timestamp": entry.site_report_timestamp,
                }
            )
        if entry.mail_report_id is not None:
            mail.append(
                {
                    "permalink": f"/mail/{entry.domain}/{entry.mail_report_id}/",
                    "domain": entry.domain,
                    "timestamp": entry.mail_report_timestamp,
                }
            )
        if entry.site_report_id is not None and entry.mail_report_id is not None:
            timestamp = entry.mail_report_timestamp
            permalink = f"/mail/{entry.domain}/{entry.mail_report_id}/"
            if entry.site_report_timestamp > entry.mail_report_timestamp:
                timestamp = entry.site_report_timestamp
                permalink = f"/site/{entry.domain}/{entry.site_report_id}/"
            champions.append({"permalink": permalink, "domain": entry.domain, "timestamp": timestamp})
    champions = sorted(champions, key=lambda x: x["timestamp"], reverse=True)
    web = sorted(web, key=lambda x: x["timestamp"], reverse=True)
    mail = sorted(mail, key=lambda x: x["timestamp"], reverse=True)

    for data, red_id in ((champions, redis_id.hof_champions), (web, redis_id.hof_web), (mail, redis_id.hof_mail)):
        cached_data = {"date": None, "count": 0, "data": data}
        if cached_data["data"]:
            cached_data["date"] = cached_data["data"][0]["timestamp"]
            cached_data["count"] = len(cached_data["data"])
            cache_id = red_id.id
            cache_ttl = red_id.ttl
            cache.set(cache_id, cached_data, cache_ttl)


@shared_task
def update_hof():
    lock_id = redis_id.hof_lock.id
    lock_ttl = redis_id.hof_lock.ttl
    with util.memcache_lock(lock_id, lock_ttl) as acquired:
        if acquired:
            _update_hof()
