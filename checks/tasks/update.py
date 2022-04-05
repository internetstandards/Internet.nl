# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
from celery import shared_task
from celery.utils.log import get_task_logger
from django.core.cache import cache
from django.db import transaction

from checks.models import DomainTestReport, MailTestReport
from interface import redis_id
from interface.batch import util

logger = get_task_logger(__name__)


class HOFEntry(object):
    def __init__(self, domain):
        self.domain = domain
        self.web_timestamp = None
        self.web_permalink = None
        self.mail_timestamp = None
        self.mail_permalink = None
        self.mail_nomx = None

    def __str__(self):
        return f"""------- {self.domain}
        web_timestamp: {self.web_timestamp}
        web_permalink: {self.web_permalink}
        mail_timestamp: {self.mail_timestamp}
        mail_permalink: {self.mail_permalink}
        mail_nomx: {self.mail_nomx}
        """


def _create_hof_entry(hof, domain_name):
    """
    Create an entry in the Hall of Fame.

    """
    if domain_name in hof:
        return hof[domain_name]
    hof[domain_name] = HOFEntry(domain_name)
    return hof[domain_name]


def _update_web_entry(hof, domain_name, report_id, timestamp):
    """
    Update a web entry in the Hall of Fame.

    """
    entry = _create_hof_entry(hof, domain_name)
    entry.web_timestamp = timestamp
    entry.web_permalink = f"/site/{domain_name}/{report_id}/"


def _update_mail_entry(hof, domain_name, report_id, timestamp):
    """
    Update a mail entry in the Hall of Fame.

    """
    entry = _create_hof_entry(hof, domain_name)
    entry.mail_timestamp = timestamp
    entry.mail_permalink = f"/mail/{domain_name}/{report_id}/"
    report = MailTestReport.objects.get(id=report_id)
    ipv6_report = report.ipv6.report
    if not isinstance(ipv6_report, dict):
        return
    entry.mail_nomx = ipv6_report["mx_aaaa"]["verdict"] == "detail mail ipv6 mx-AAAA verdict other"


def _populate_HOF(hof, model, entry_creation):
    """
    Find entries that qualify for the Hall of Fame.

    """
    previousname = None
    previousscore = 0
    previoustimestamp = None
    previousreportid = None
    for report in model.objects.all().order_by("domain", "timestamp"):
        if previousname != report.domain and previousname is not None:
            if previousscore >= 100:
                entry_creation(hof, previousname, previousreportid, previoustimestamp)
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
        entry_creation(hof, previousname, previousreportid, previoustimestamp)


@transaction.atomic
def _update_hof():
    """
    Populate the Hall of Fame with domains that scored 100% in the website
    and/or the mail test.

    .. note:: Domains that are part of the HoF are domains that their *latest*
              test scored 100%.

    """
    hof = dict()
    for model, entry_creation in ((DomainTestReport, _update_web_entry), (MailTestReport, _update_mail_entry)):
        _populate_HOF(hof, model, entry_creation)

    champions = []
    web = []
    mail = []
    for entry in hof.values():
        is_web = False
        is_mail = False
        if entry.web_permalink:
            web.append({"permalink": entry.web_permalink, "domain": entry.domain, "timestamp": entry.web_timestamp})
            is_web = True
        if entry.mail_permalink:
            mail.append({"permalink": entry.mail_permalink, "domain": entry.domain, "timestamp": entry.mail_timestamp})
            is_mail = True
        if is_web and is_mail:
            timestamp = entry.mail_timestamp
            permalink = entry.mail_permalink
            if entry.web_timestamp > entry.mail_timestamp:
                timestamp = entry.web_timestamp
                permalink = entry.web_permalink
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
