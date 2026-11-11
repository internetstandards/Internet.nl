# Copyright: 2022, ECP, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
from itertools import groupby
from operator import attrgetter

from celery import shared_task
from celery.utils.log import get_task_logger
from django.conf import settings
from django.core.cache import cache
from django.db import transaction
from django.db.models import Count, Q

from checks.models import ConnectionTest, DomainTestReport, MailTestReport
from interface import redis_id
from interface.batch import util

logger = get_task_logger(__name__)


def _perfect_scores(model):
    """
    Return the domains whose latest test scored 100%, as
    {domain: (start of its current run of 100% scores, latest report id)}, and the number of domains tested.

    """
    perfect = {}
    tested = 0
    reports = model.objects.only("id", "domain", "timestamp", "score").order_by("domain", "timestamp")
    for domain, domain_reports in groupby(reports.iterator(), key=attrgetter("domain")):
        tested += 1
        since = None
        for report in domain_reports:
            if (report.score or 0) < 100:
                since = None
            elif since is None:
                since = report.timestamp
        if since is not None:
            perfect[domain] = (since, report.id)
    return perfect, tested


def _numbers(tested, perfect):
    return {"tested": tested, "percent": round(100 * perfect / tested) if tested else 0}


@transaction.atomic
def _update_hof():
    """
    Cache the Hall of Fame champions, the domains whose latest website and mail tests both scored 100%,
    and the numbers for the homepage.

    """
    web, web_tested = _perfect_scores(DomainTestReport)
    mail, mail_tested = _perfect_scores(MailTestReport)
    champions = []
    for domain in web.keys() & mail.keys():
        web_timestamp, web_report_id = web[domain]
        mail_timestamp, mail_report_id = mail[domain]
        if web_timestamp > mail_timestamp:
            permalink, timestamp = f"/site/{domain}/{web_report_id}/", web_timestamp
        else:
            permalink, timestamp = f"/mail/{domain}/{mail_report_id}/", mail_timestamp
        champions.append({"permalink": permalink, "domain": domain, "timestamp": timestamp})
    champions = sorted(champions, key=lambda x: x["timestamp"], reverse=True)

    cached_data = {"count": len(champions), "data": champions[: settings.HOF_CHAMPIONS_LIMIT]}
    cache.set(redis_id.hof_champions.id, cached_data, redis_id.hof_champions.ttl)

    connection = ConnectionTest.objects.filter(finished=True).aggregate(
        tested=Count("id"), perfect=Count("id", filter=Q(score_ipv6=100, score_dnssec=100))
    )
    numbers = {
        "web": _numbers(web_tested, len(web)),
        "mail": _numbers(mail_tested, len(mail)),
        "connection": _numbers(connection["tested"], connection["perfect"]),
    }
    cache.set(redis_id.home_stats.id, numbers, redis_id.home_stats.ttl)


@shared_task
def update_hof():
    lock_id = redis_id.hof_lock.id
    lock_ttl = redis_id.hof_lock.ttl
    with util.memcache_lock(lock_id, lock_ttl) as acquired:
        if acquired:
            _update_hof()
