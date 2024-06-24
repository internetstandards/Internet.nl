# Copyright: 2022, ECP, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
import random
from timeit import default_timer as timer
from typing import Optional, Dict, Tuple, Union, Callable

from celery.utils.log import get_task_logger
from django.conf import settings
from django.core.cache import cache
from django.utils import timezone
from pyrabbit2 import Client
from pyrabbit2.api import APIError, PermissionError
from pyrabbit2.http import HTTPError, NetworkError

from checks.models import (
    BatchDomain,
    BatchDomainStatus,
    BatchRequest,
    BatchRequestStatus,
    BatchTestStatus,
    BatchWebTest,
    DomainTestDnssec,
    DomainTestReport,
    MailTestDnssec,
    MailTestReport,
    MailTestTls,
    WebTestAppsecpriv,
    WebTestTls,
    BatchUser,
    BaseTestModel,
    BatchMailTest,
)

from checks.probes import batch_mailprobes, batch_webprobes
from checks.tasks import dispatcher
from interface import batch_shared_task, redis_id
from interface.batch import util

logger = get_task_logger(__name__)

BatchTests = Union[BatchWebTest, BatchMailTest]
BATCH_WEBTEST = {"subtests": {}, "report": {"name": "domaintestreport"}}
BATCH_MAILTEST = {"subtests": {}, "report": {"name": "mailtestreport"}}
MAX_SUBTEST_ATTEMPTS = 3

if settings.INTERNET_NL_CHECK_SUPPORT_IPV6:
    from checks.tasks.ipv6 import batch_web_registered as ipv6_web_taskset

    BATCH_WEBTEST["subtests"]["ipv6"] = ipv6_web_taskset
    from checks.tasks.ipv6 import batch_mail_registered as ipv6_mail_taskset

    BATCH_MAILTEST["subtests"]["ipv6"] = ipv6_mail_taskset

if settings.INTERNET_NL_CHECK_SUPPORT_DNSSEC:
    from checks.tasks.dnssec import batch_web_registered as dnssec_web_taskset

    BATCH_WEBTEST["subtests"]["dnssec"] = dnssec_web_taskset
    from checks.tasks.dnssec import batch_mail_registered as dnssec_mail_taskset

    BATCH_MAILTEST["subtests"]["dnssec"] = dnssec_mail_taskset

if settings.INTERNET_NL_CHECK_SUPPORT_TLS:
    from checks.tasks.tls import batch_web_registered as tls_web_taskset

    BATCH_WEBTEST["subtests"]["tls"] = tls_web_taskset
    from checks.tasks.tls import batch_mail_registered as tls_mail_taskset

    BATCH_MAILTEST["subtests"]["tls"] = tls_mail_taskset

if settings.INTERNET_NL_CHECK_SUPPORT_RPKI:
    from checks.tasks.rpki import batch_web_registered as rpki_web_taskset

    BATCH_WEBTEST["subtests"]["rpki"] = rpki_web_taskset
    from checks.tasks.rpki import batch_mail_registered as rpki_mail_taskset

    BATCH_MAILTEST["subtests"]["rpki"] = rpki_mail_taskset

if settings.INTERNET_NL_CHECK_SUPPORT_APPSECPRIV:
    from checks.tasks.appsecpriv import batch_web_registered as appsecpriv_web_taskset

    BATCH_WEBTEST["subtests"]["appsecpriv"] = appsecpriv_web_taskset

if settings.INTERNET_NL_CHECK_SUPPORT_MAIL:
    from checks.tasks.mail import batch_mail_registered as auth_mail_taskset

    BATCH_MAILTEST["subtests"]["auth"] = auth_mail_taskset


class Rabbit:
    """
    Wrapper class for the pyrabbit client.

    """

    def __init__(self, rabbit, user, password):
        self._rabbit = rabbit
        self._user = user
        self._pass = password

    def _get_client(self):
        """
        Get a client connection to rabbitmq.

        """
        try:
            self._cl = Client(self._rabbit, self._user, self._pass)
            return True
        except (HTTPError, NetworkError, APIError, PermissionError):
            return None

    def get_queue_depth(self, host, queue):
        """
        Get the size of a queue on a rabbitmq virtual host.
        In case of a random exception, retry before failing.

        """
        tries = 5
        while tries > 0:
            try:
                return self._cl.get_queue_depth(host, queue)
            except (AttributeError, HTTPError, NetworkError, APIError, PermissionError) as e:
                self._get_client()
                tries -= 1
                if tries <= 0:
                    raise e


def is_queue_loaded(client):
    """
    Check if we consider the monitor queue loaded.

    """
    for queue_name in settings.RABBIT_MON_QUEUES:
        current_load = client.get_queue_depth(settings.RABBIT_VHOST, queue_name)
        if current_load >= settings.RABBIT_MON_THRESHOLD:
            return True
    return False


def get_live_requests() -> Dict[BatchUser, BatchRequest]:
    """
    Return a dictionary with active users as keys and their earliest
    live batch request as value.

    """
    live_requests = dict()
    batch_requests = BatchRequest.objects.filter(status=BatchRequestStatus.live).order_by("submit_date")
    for request in batch_requests:
        if not live_requests.get(request.user):
            live_requests[request.user] = request
    return live_requests


def get_user_and_request(live_requests) -> Tuple[Optional[BatchUser], Optional[BatchRequest]]:
    """
    Pick a user and his request from the available live_requests.
    Users are fairly chosen regardless of the number of submitted tests.

    """
    if not live_requests:
        return None, None

    user = random.choice(list(live_requests.keys()))
    batch_request = live_requests[user]
    return user, batch_request


def pick_domain(batch_request) -> Optional[BatchDomain]:
    """
    Pick a domain to test.
    Selects the first available domain.
    """
    return BatchDomain.objects.filter(status=BatchDomainStatus.waiting, batch_request=batch_request).first()


def check_for_result_or_start_test(batch_domain: BatchDomain, batch_test: BatchTests, subtest: str, taskset: Callable):
    """
    Link the result if already available or start a test.

    """
    started_test = False
    subtest_model = batch_test._meta.get_field(subtest).remote_field.model
    result = find_result(batch_domain, subtest_model)
    if result:
        save_result(batch_test, subtest, result)
    else:
        start_test(batch_domain, batch_test, subtest, taskset)
        started_test = True
    return started_test


def find_result(batch_domain, model):
    """
    Check if we already have results for the domain. Viable results are
    ones recorded after the batch submission.

    """
    submit_date = batch_domain.batch_request.submit_date
    try:
        if model is WebTestTls:
            result = model.objects.filter(domain=batch_domain.domain, webtestset__timestamp__gte=submit_date).latest(
                "id"
            )
        elif model is MailTestTls:
            result = model.objects.filter(domain=batch_domain.domain, testset__timestamp__gte=submit_date).latest("id")
        elif model is MailTestDnssec:
            result = model.objects.filter(domain=batch_domain.domain, testset__timestamp__gte=submit_date).latest("id")
        elif model is WebTestAppsecpriv:
            result = model.objects.filter(domain=batch_domain.domain, webtestset__timestamp__gte=submit_date).latest(
                "id"
            )
        elif model is DomainTestDnssec:
            result = model.objects.filter(
                domain=batch_domain.domain, maildomain_id=None, timestamp__gte=submit_date
            ).latest("id")
        else:
            result = model.objects.filter(domain=batch_domain.domain, timestamp__gte=submit_date).latest("id")
    except model.DoesNotExist:
        result = None
    return result


def save_result(batch_test: BatchTests, subtest: str, result):
    """
    Link results and save model.

    """
    setattr(batch_test, subtest, result)
    setattr(batch_test, f"{subtest}_status", BatchTestStatus.done)
    batch_test.save(update_fields=[f"{subtest}_id", f"{subtest}_status"])
    logger.info(
        f"domain {getattr(result, 'domain', None)}: {batch_test.__class__.__name__} finished task for subtest {subtest}"
    )


def start_test(batch_domain: BatchDomain, batch_test: BatchTests, subtest: str, taskset: Callable):
    """
    Submit test and change status to running.

    """
    submit_test(batch_domain, subtest, taskset)
    setattr(batch_test, f"{subtest}_status", BatchTestStatus.running)
    batch_test.save(update_fields=[f"{subtest}_status"])


def submit_test(batch_domain: BatchDomain, test: str, checks_registry: Callable):
    """
    Submit the test in celery.

    """
    url = batch_domain.domain
    task_set = dispatcher.submit_task_set(url, checks_registry, error_cb=error_callback)
    # Need to cache it in redis, then the callback can look it up based
    # on the task id.
    cache_id = redis_id.running_batch_test.id.format(task_set.id)
    cache_ttl = redis_id.running_batch_test.ttl
    cache.set(cache_id, (batch_domain.id, test), cache_ttl)
    logger.info(f"domain {batch_domain.domain}: started task {task_set.id} for subtest {test}")

    return task_set


def check_any_subtest_for_status(batch_test, status):
    """
    Check if any of the subtests has a given status.

    """
    if isinstance(batch_test, BatchWebTest):
        subtests = BATCH_WEBTEST["subtests"]
    else:
        subtests = BATCH_MAILTEST["subtests"]

    for subtest in subtests:
        if getattr(batch_test, f"{subtest}_status") == status:
            return True

    return False


def find_or_create_report(batch_domain):
    report = get_common_report(batch_domain)
    if report:
        batch_test = batch_domain.get_batch_test()
        batch_test.report = report
        batch_test.save(update_fields=["report"])
    else:
        create_report(batch_domain)


def get_common_report(batch_domain):
    """
    Try to find the most recent common report for all subtests.
    If no such report exists or at least one of the subtests is not yet
    part of a report return nothing.

    """
    batch_test = batch_domain.get_batch_test()
    if isinstance(batch_test, BatchWebTest):
        subtests = BATCH_WEBTEST["subtests"]
        report_details = BATCH_WEBTEST["report"]
    else:
        subtests = BATCH_MAILTEST["subtests"]
        report_details = BATCH_MAILTEST["report"]

    report_ids = {}
    for subtest in subtests:
        report_ids[subtest] = set()
        # example: batch_test.ipv6.mailtestreport_set.all()
        for report in getattr(getattr(batch_test, subtest), "{}_set".format(report_details["name"])).all():
            report_ids[subtest].add(report.id)

        if not report_ids[subtest]:
            return None

    for i, subtest in enumerate(report_ids):
        if i == 0:
            common_report_ids = report_ids[subtest]
        else:
            common_report_ids.intersection_update(report_ids[subtest])

    if common_report_ids:
        common_report_id = max(common_report_ids)
        report_model = batch_test._meta.get_field("report").remote_field.model
        try:
            return report_model.objects.get(id=common_report_id)
        except report_model.DoesNotExist:
            pass
    return None


def create_report(batch_domain):
    """
    Create the report for this domain.
    Similar to when a user is redirected to the results page.

    """
    domain = batch_domain.domain
    if batch_domain.webtest:
        batch_test = batch_domain.webtest
        report = DomainTestReport(
            domain=domain,
            ipv6=batch_test.ipv6,
            dnssec=batch_test.dnssec,
            tls=batch_test.tls,
            appsecpriv=batch_test.appsecpriv,
            rpki=batch_test.rpki,
        )
        probe_reports = batch_webprobes.get_probe_reports(report)
        score = batch_webprobes.count_probe_reports_score(probe_reports)
    else:
        batch_test = batch_domain.mailtest
        report = MailTestReport(
            domain=domain,
            ipv6=batch_test.ipv6,
            dnssec=batch_test.dnssec,
            auth=batch_test.auth,
            tls=batch_test.tls,
            rpki=batch_test.rpki,
        )
        probe_reports = batch_mailprobes.get_probe_reports(report)
        score = batch_mailprobes.count_probe_reports_score(probe_reports)

    report.registrar = "-Not available in batch-"
    report.score = score
    report.save()
    batch_test.report = report
    batch_test.save()


def update_domain_status(batch_domain: BatchDomain):
    """
    Check the status of the individual tests and update the domain's
    entry status.

    """
    if batch_domain.status == BatchDomainStatus.cancelled:
        return

    batch_test = batch_domain.get_batch_test()

    if check_any_subtest_for_status(batch_test, BatchTestStatus.error):
        batch_domain.status = BatchDomainStatus.error
    elif check_any_subtest_for_status(batch_test, BatchTestStatus.waiting):
        batch_domain.status = BatchDomainStatus.waiting
    elif check_any_subtest_for_status(batch_test, BatchTestStatus.running):
        batch_domain.status = BatchDomainStatus.running
    else:
        batch_domain.status = BatchDomainStatus.done
        find_or_create_report(batch_domain)
    batch_domain.status_changed = timezone.now()
    batch_domain.save(update_fields=["status_changed", "status"])


def update_batch_status(batch_request: BatchRequest):
    """
    Check the status of the submitted domains and update the batch
    request's status if necessary.

    """
    if batch_request.status in (
        BatchRequestStatus.cancelled,
        BatchRequestStatus.done,
        BatchRequestStatus.registering,
        BatchRequestStatus.error,
    ):
        return

    waiting = batch_request.domains.filter(status=BatchDomainStatus.waiting).exists()
    running = batch_request.domains.filter(status=BatchDomainStatus.running).exists()
    if not waiting:
        if running:
            batch_request.status = BatchRequestStatus.running
        else:
            batch_request.status = BatchRequestStatus.done
            batch_request.finished_date = timezone.now()
    else:
        batch_request.status = BatchRequestStatus.live
    batch_request.save(update_fields=["status", "finished_date"])


def batch_callback_hook(result: Optional[BaseTestModel], task_id: str):
    """
    Link the result and change the status of the running test.

    """
    if not result:
        logger.error(f"batch callback for task {task_id} called without result")
        return

    cache_id = redis_id.running_batch_test.id.format(task_id)
    cached = cache.get(cache_id)
    if not cached:
        domain = getattr(result, "domain", None)
        logger.error(f"batch callback could not find task {task_id} in cache (cache ID {cache_id}, domain {domain})")
        return

    batch_domain_id, subtest = cached
    batch_domain = BatchDomain.objects.get(id=batch_domain_id)
    if batch_domain.status == BatchDomainStatus.cancelled:
        return

    batch_test = batch_domain.get_batch_test()

    save_result(batch_test, subtest, result)
    cache.delete(cache_id)

    update_domain_status(batch_domain)


@batch_shared_task()
def error_callback(request, exc, traceback):
    """
    Increase error count and change status, if an error occurs.

    .. note:: Celery only calls this when there is an exception in the chord
              callback. This is a bug in celery. To compensate we periodically
              check for tests stuck in the running state with
              find_stalled_tests_and_update_db().

    """
    logger.error(f"Task {request.id!r} raised error: {exc!r}")
    cache_id = redis_id.running_batch_test.id.format(request.id)
    cached = cache.get(cache_id)
    if not cached:
        logger.error("Error callback, could not find task id '{}'" "".format(request.id))
        return

    batch_domain_id, test = cached
    batch_domain = BatchDomain.objects.get(id=batch_domain_id)
    if batch_domain.status == BatchDomainStatus.cancelled:
        return

    batch_test = batch_domain.get_batch_test()
    record_subtest_error(batch_test, test)
    update_domain_status(batch_domain)
    cache.delete(cache_id)


def record_subtest_error(batch_test, subtest):
    """
    Increase and return the error count for the given subtest. Also change
    the status if appropriate.

    """
    error_count = getattr(batch_test, f"{subtest}_errors")
    status = getattr(batch_test, f"{subtest}_status")
    error_count += 1
    if status != BatchTestStatus.cancelled:
        if error_count >= MAX_SUBTEST_ATTEMPTS:
            status = BatchTestStatus.error
        else:
            status = BatchTestStatus.waiting
        setattr(batch_test, f"{subtest}_status", status)
    setattr(batch_test, f"{subtest}_errors", error_count)
    batch_test.save(update_fields=[f"{subtest}_status", f"{subtest}_errors"])
    return error_count


def find_stalled_tests_and_update_db():
    """
    Find tests that have been in the running state for more than a given
    threshold and update their status.

    """
    running_domains = BatchDomain.objects.filter(status=BatchDomainStatus.running)
    now = timezone.now()
    for batch_domain in running_domains:
        timediff = (now - batch_domain.status_changed).total_seconds()
        if timediff >= settings.BATCH_MAX_RUNNING_TIME:
            if batch_domain.webtest:
                batch_test = batch_domain.webtest
                subtests = BATCH_WEBTEST["subtests"]
            else:
                batch_test = batch_domain.mailtest
                subtests = BATCH_MAILTEST["subtests"]

            for subtest in subtests:
                status = getattr(batch_test, f"{subtest}_status")
                if status == BatchTestStatus.running:
                    errors = record_subtest_error(batch_test, subtest)
                    logger.info(
                        f"domain {batch_domain.domain}: subtest {subtest} failed to complete in time (attempt {errors})"
                    )
            update_domain_status(batch_domain)


def update_batch_request_status():
    batch_requests = BatchRequest.objects.filter(status__in=(BatchRequestStatus.live, BatchRequestStatus.running))
    for batch_request in batch_requests:
        update_batch_status(batch_request)


def _run_scheduler():
    """
    Submit a fixed number of domains for testing if the queue is not
    considered loaded.

    """
    client = Rabbit(settings.RABBIT_HOST, settings.RABBIT_USER, settings.RABBIT_PASS)
    domains_to_test = settings.BATCH_SCHEDULER_DOMAINS

    start_time = timer()
    find_stalled_tests_and_update_db()
    logger.info(f"Found stalled tests in {timer() - start_time}s")

    start_time = timer()
    update_batch_request_status()
    logger.info(f"Updated batch request status in {timer() - start_time}s")

    submitted_domains = 0
    found_domains = 0
    start_time = timer()
    live_requests = get_live_requests()
    if not is_queue_loaded(client):
        while domains_to_test > 0:
            user, batch_request = get_user_and_request(live_requests)
            if not user or not batch_request:
                break

            batch_domain = pick_domain(batch_request)
            if not batch_domain:
                break

            subtests_started = 0
            batch_test = batch_domain.get_batch_test()
            if isinstance(batch_test, BatchWebTest):
                subtests = BATCH_WEBTEST["subtests"]
            else:
                subtests = BATCH_MAILTEST["subtests"]

            for subtest in subtests:
                if getattr(batch_test, f"{subtest}_status") == BatchTestStatus.waiting:
                    started_test = check_for_result_or_start_test(batch_domain, batch_test, subtest, subtests[subtest])
                    if started_test:
                        subtests_started += 1

            if subtests_started > 0:
                submitted_domains += 1
                domains_to_test -= 1
            else:
                found_domains += 1
            update_domain_status(batch_domain)
        logger.info(
            f"Submitted {submitted_domains} domains in {format(timer() - start_time)}s, "
            f"{len(live_requests)} users remaining in queue"
        )
    else:
        logger.info(
            f"No domains submitted, queue is currently too loaded, {len(live_requests)} users remaining in queue"
        )
    logger.info(f"Found {found_domains} domains")


@batch_shared_task
def run():
    """
    Run the scheduler every interval only if it is not running already.

    """
    lock_id = redis_id.batch_scheduler_lock.id
    lock_ttl = redis_id.batch_scheduler_lock.ttl
    with util.memcache_lock(lock_id, lock_ttl) as acquired:
        if acquired:
            _run_scheduler()
            return
    logger.info("Already running...")
