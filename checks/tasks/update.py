# Copyright: 2022, ECP, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
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
    Return the domains whose latest test scored 100%, as {domain: (since when it scores 100%, latest report id)},
    and the number of domains tested.

    """
    perfect = {}
    tested = 0
    previousname = None
    previousscore = 0
    previoustimestamp = None
    previousreportid = None
    for report in model.objects.only("id", "domain", "timestamp", "score").order_by("domain", "timestamp").iterator():
        if report.domain != previousname:
            tested += 1
        if previousname != report.domain and previousname is not None:
            if previousscore >= 100:
                perfect[previousname] = (previoustimestamp, previousreportid)
            previousname = report.domain
            previousscore = report.score or 0
            previoustimestamp = report.timestamp
            previousreportid = report.id

        else:
            report_score = report.score or 0
            if report_score != previousscore:
                previoustimestamp = report.timestamp
            previousname = report.domain
            previousreportid = report.id
            previousscore = report_score

    # Last domain name.
    if previousscore >= 100:
        perfect[previousname] = (previoustimestamp, previousreportid)
    return perfect, tested


def _numbers(tested, perfect):
    return {"tested": tested, "percent": round(100 * perfect / tested) if tested else 0}


@transaction.atomic
def _update_hof():
    """
    Populate the Hall of Fame with domains that scored 100% in the website
    and the mail test, and count the tests for the homepage.

    .. note:: Domains that are part of the HoF are domains that their *latest*
              test scored 100%.

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
