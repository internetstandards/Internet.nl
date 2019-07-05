# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
from celery.task.schedules import crontab
from celery.decorators import periodic_task
from celery.utils.log import get_task_logger
from django.db import transaction
from django.core.cache import cache

from .. import redis_id
from ..models import Ranking, DomainTestReport
from ..batch import util

logger = get_task_logger(__name__)


def _create_hof_entry(
        domain_name, report_id, score, timestamp,
        entry_type=Ranking.TYPE_WEBSITE):
    """
    Create an entry in the Hall of Fame.

    """
    ranking = Ranking()
    ranking.type = entry_type
    ranking.name = domain_name
    ranking.score = score
    ranking.timestamp = timestamp
    ranking.permalink = "/site/{}/{}/".format(
        ranking.name, str(report_id))
    ranking.save()


@transaction.atomic
def _update_hof():
    """
    Populate the Hall of Fame with domains that scored 100% in the website
    test.

    .. note:: Domains that are part of the HoF are domains that their latest
              test scored 100%.

    """
    Ranking.objects.all().delete()
    previousname = None
    previousscore = 0
    previoustimestamp = None
    previousreportid = None
    for report in DomainTestReport.objects.all().order_by('domain',
                                                          'timestamp'):
        if previousname != report.domain and previousname is not None:
            if previousscore >= 100:
                _create_hof_entry(
                    domain_name=previousname,
                    report_id=previousreportid,
                    score=previousscore,
                    timestamp=previoustimestamp)
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
        _create_hof_entry(
            domain_name=previousname,
            report_id=previousreportid,
            score=previousscore,
            timestamp=previoustimestamp)

    # Store HoF in cache to avoid DB queries.
    # TODO: Do we even need HoF in DB anymore?
    cached_data = {'date': None, 'count': 0, 'data': []}
    for ranking in Ranking.objects.order_by('-timestamp'):
        cached_data['data'].append({
            'permalink': ranking.permalink, 'name': ranking.name,
            'timestamp': ranking.timestamp})
    if cached_data['data']:
        cached_data['date'] = cached_data['data'][0]['timestamp']
        cached_data['count'] = len(cached_data['data'])
        cache_id = redis_id.hof_data.id
        cache_ttl = redis_id.hof_data.ttl
        cache.set(cache_id, cached_data, cache_ttl)


@periodic_task(run_every=(crontab(hour="*", minute="*/10", day_of_week="*")))
def ranking():
    lock_id = redis_id.hof_lock.id
    lock_ttl = redis_id.hof_lock.ttl
    with util.memcache_lock(lock_id, lock_ttl) as acquired:
        if acquired:
            _update_hof()
