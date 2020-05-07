# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
import inspect
import random
import re
import json
from collections import defaultdict
from functools import wraps

from celery.five import monotonic
from contextlib import contextmanager
from django.conf import settings
from django.core.cache import cache
from django.core.files.base import ContentFile
from django.core.urlresolvers import reverse
from django.db import transaction
from django.utils import timezone

from . import BATCH_API_FULL_VERSION, REPORT_METADATA_WEB_MAP
from . import REPORT_METADATA_MAIL_MAP
from . import BATCH_PROBE_NAME_TO_API_CATEGORY, BATCH_API_CATEGORY_TO_PROBE_NAME
from .responses import api_response, unauthorised_response
from .responses import bad_client_request_response, general_server_error
from .custom_results import CUSTOM_RESULTS_MAP
from .. import batch_shared_task, redis_id
from ..probes import batch_webprobes, batch_mailprobes
from ..models import BatchUser, BatchRequestType, BatchDomainStatus
from ..models import BatchCustomView, BatchWebTest, BatchMailTest
from ..models import BatchDomain, BatchRequestStatus, BatchRequest
from ..views.shared import pretty_domain_name, validate_dname
from ..templatetags.translate import render_details_table


verdict_regex = re.compile(
    r'^detail (?:[^\s]+ [^\s]+ [^\s]+ )?verdict ([^\s]+)$',
    flags=re.I)
statuses = {
    0: 'failed',
    1: 'passed',
    2: 'warning',
    3: 'good_not_tested',
    4: 'not_tested',
    5: 'info',
}


def get_site_url(request):
    """
    Compose the url that the user used to connect to the API.

    """
    return "{}://{}".format(request.scheme, request.get_host())


def check_valid_user(function):
    """
    Custom decorator for batch views.
    Check if the authenticated user is a user in the batch database and make
    the record available in the decorated function.

    """
    @wraps(function)
    def wrap(request, *args, **kwargs):
        user = get_user_from_request(request)
        if not user:
            return unauthorised_response()
        kwargs['batch_user'] = user
        return function(request, *args, **kwargs)

    return wrap


def get_user_from_request(request):
    """
    If the user that made the request is a legitimate batch user (exists in the
    DB) return the relevant user object from the DB.

    """
    user = None
    try:
        username = (
            request.META.get('REMOTE_USER')
            or request.META.get('HTTP_REMOTE_USER'))
        if not username:
            username = getattr(settings, 'BATCH_TEST_USER', None)
        user = BatchUser.objects.get(username=username)
    except BatchUser.DoesNotExist:
        pass
    return user


class ReportMetadata:
    def _parse_report_item(
            self, item, hierarchy, data, name_map, probeset, category=None):
        data[item['name']] = {
            'type': item['type'],
            'translation_key': item['translation_key'],
        }
        hier = {'name': item['name']}

        if 'children' in item:
            hier['children'] = []

            # Initialise the category if visiting a category's children.
            if item['type'] == "category":
                probe_name = BATCH_API_CATEGORY_TO_PROBE_NAME[item['name']]
                category = probeset[probe_name].category()

            for child in item['children']:
                self._parse_report_item(
                    child, hier['children'], data, name_map, probeset, category)
        hierarchy.append(hier)
        if item['type'] != "test":
            return
        self._gather_status_verdict_map(item, data, name_map, category)

    def _gather_status_verdict_map(self, item, data, name_map, category):
        # Continue here for test items.
        name_map[item['name_on_report']] = item['name']

        status_verdict_map = defaultdict(set)

        testname = item['name_on_report']
        subtest = category.subtests[testname]

        result_methods = [
            method[1]
            for method in inspect.getmembers(
                subtest, predicate=inspect.ismethod)
            if method[0].startswith('result_')
        ]
        for method in result_methods:
            subtest.__init__()
            arg_len = len(inspect.signature(method).parameters)
            if arg_len:
                method({None for i in range(arg_len)})
            else:
                method()
            status = statuses[subtest.status]
            fullverdict = verdict_regex.fullmatch(subtest.verdict).group(0)
            if fullverdict in (
                    "detail verdict not-tested",
                    "detail verdict could-not-test"):
                verdict = fullverdict
            else:
                verdict = verdict_regex.fullmatch(subtest.verdict).group(1)
            status_verdict_map[status].add(verdict)
        # Add the default status/verdict for each test.
        status_verdict_map['not_tested'].add("detail verdict not-tested")
        # Make it JSON serialisable.
        data[item['name']]['status_verdict_map'] = {
            status: list(verdicts)
            for status, verdicts in status_verdict_map.items()
        }

    def build_report_metadata(self):
        res = {}
        res['hierarchy'] = {
            'web': [],
            'mail': []
        }
        res['data'] = {}
        res['name_map'] = {}
        for item in REPORT_METADATA_WEB_MAP:
            self._parse_report_item(
                item, res['hierarchy']['web'], res['data'], res['name_map'],
                batch_webprobes)

        for item in REPORT_METADATA_MAIL_MAP:
            self._parse_report_item(
                item, res['hierarchy']['mail'], res['data'], res['name_map'],
                batch_mailprobes)

        return res


def get_report_metadata():
    cache_id = redis_id.report_metadata.id
    return cache.get(cache_id)


@contextmanager
def memcache_lock(lock_id, lock_duration=60*5):
    """
    Simple cache lock to keep celerybeat tasks from running before the previous
    execution has not finished yet.

    Also used for simple tasks that may be triggered more than one for the same
    task.

    .. note:: Mostly as documented in the celery documentation.

    """
    if lock_duration is not None:
        timeout_at = monotonic() + lock_duration - 3
    # cache.add fails if the key already exists
    status = cache.add(lock_id, True, lock_duration)
    try:
        yield status
    finally:
        # memcache delete is very slow, but we have to use it to take
        # advantage of using add() for atomic locking
        if lock_duration is None or (monotonic() < timeout_at and status):
            # don't release the lock if we exceeded the timeout
            # to lessen the chance of releasing an expired lock
            # owned by someone else
            # also don't release the lock if we didn't acquire it
            cache.delete(lock_id)


@batch_shared_task(bind=True, ignore_result=True)
def batch_async_generate_results(self, user, batch_request, site_url):
    """
    Generate the batch results and save to file.

    """
    lock_id_name = redis_id.batch_results_lock.id
    lock_ttl = redis_id.batch_results_lock.ttl

    def on_failure(exc, task_id, args, kwargs, einfo):
        """
        Custom on_failure function to delete state from cache.

        """
        user = kwargs['user']
        batch_request = kwargs['batch_request']
        lock_id = lock_id_name.format(
            user.username, batch_request.request_id)
        cache.delete(lock_id)

    self.on_failure = on_failure

    lock_id = lock_id_name.format(user.username, batch_request.request_id)
    batch_request.refresh_from_db()
    if not batch_request.has_report_file():
        with memcache_lock(lock_id, lock_ttl) as acquired:
            if acquired:
                results = gather_batch_results(user, batch_request, site_url)
                save_batch_results_to_file(user, batch_request, results)


def gather_batch_results(user, batch_request, site_url):
    """
    Gather all the results for the batch request and return them in a
    dictionary that will be eventually converted to JSON for the API answer.

    """
    data = {
        "api_version": BATCH_API_FULL_VERSION,
        "request": batch_request.to_api_dict()
    }
    # Technically the status is still generating.
    data['request']['status'] = "done"

    if batch_request.type is BatchRequestType.web:
        probes = batch_webprobes.getset()
        url_name = 'webtest_results'
        url_arg = ['site']
        related_testset = 'webtest'
    else:
        probes = batch_mailprobes.getset()
        url_name = 'mailtest_results'
        url_arg = []
        related_testset = 'mailtest'

    dom_results = {}

    # Quering for the related rows upfront minimizes further DB queries and
    # gives ~33% boost to performance.
    related_fields = []
    for probe in probes:
        related_fields.append(
            '{}__report__{}'.format(related_testset, probe.name))

    batch_domains = batch_request.domains.all().select_related(*related_fields)
    for batch_domain in batch_domains:
        result = {}
        domain_name_idna = pretty_domain_name(batch_domain.domain)
        dom_results[domain_name_idna] = result
        if batch_domain.status == BatchDomainStatus.error:
            result['status'] = "error"
            continue

        batch_test = batch_domain.get_batch_test()
        report_table = batch_test.report
        score = report_table.score

        args = url_arg + [batch_domain.domain, report_table.id]
        result['report'] = {
            'url': "{}{}".format(site_url, reverse(url_name, args=args))
        }
        result['scoring'] = {"percentage": score}

        tests = {}
        categories = {}
        customs = {}
        result['results'] = {
            "categories": categories,
            "tests": tests,
            "custom": customs
        }

        for probe in probes:
            category = BATCH_PROBE_NAME_TO_API_CATEGORY[probe.prefix+probe.name]
            model = getattr(report_table, probe.name)
            _, _, verdict = probe.get_scores_and_verdict(model)
            categories[category] = {
                "verdict": verdict,
                "status": verdict
            }

            name_map = cache.get(redis_id.batch_metadata.id)
            report = model.report
            for subtest, sub_data in report.items():
                if name_map.get(subtest):
                    status = statuses[sub_data['status']]
                    verdict = (
                        verdict_regex.fullmatch(sub_data['verdict']).group(1))
                    res = []
                    if sub_data['tech_type']:
                        res = render_details_table(
                            sub_data['tech_string'],
                            sub_data['tech_data'])['details_table_rows']
                    tests[name_map[subtest]] = {
                        "status": status,
                        "verdict": verdict,
                        "technical_details": res
                    }

        for custom_result in (
                r for r, active
                in settings.BATCH_API_CUSTOM_RESULTS.items() if active):
            custom_instance = CUSTOM_RESULTS_MAP[custom_result]
            custom_data = custom_instance.get_data(
                batch_request.type, batch_domain)
            if custom_data:
                customs[custom_instance.name] = custom_data

    data['domains'] = dom_results
    return data


def save_batch_results_to_file(user, batch_request, results):
    """
    Save results to file using the Django's ORM utilities.

    """
    filename = '{}-{}-{}.json'.format(
        user.username, batch_request.type.label, batch_request.id)
    batch_request.report_file.save(filename, ContentFile(json.dumps(results)))


@batch_shared_task(bind=True, ignore_result=True)
@transaction.atomic
def batch_async_register(self, batch_request, test_type, domains):
    """
    Register the submitted domains for future batch testing. Domains need to
    pass validity tests similar to vanilla internet.nl. Invalid domains are not
    registered.

    """
    def on_failure(exc, task_id, args, kwargs, einfo):
        """
        Custom on_failure function to record the error.

        """
        batch_request = kwargs['batch_request']
        batch_request.refresh_from_db()
        if batch_request.status != BatchRequestStatus.cancelled:
            batch_request.status = BatchRequestStatus.error
        batch_request.finished_date = timezone.now()
        batch_request.save()

    self.on_failure = on_failure

    if test_type is BatchRequestType.web:
        batch_test_model = BatchWebTest
        keys = ('domain', 'batch_request', 'webtest')
        # Unused because of latency while registering the domains.
        # get_valid_domain = get_valid_domain_web
        get_valid_domain = validate_dname
    else:
        batch_test_model = BatchMailTest
        keys = ('domain', 'batch_request', 'mailtest')
        # Unused because of latency while registering the domains.
        # get_valid_domain = get_valid_domain_mail
        get_valid_domain = validate_dname

    for domain in domains:
        # Ignore leading/trailing whitespace.
        domain = domain.strip()
        # Only register valid domain names like vanilla internet.nl
        domain = get_valid_domain(domain)
        if not domain:
            continue

        batch_test = batch_test_model()
        batch_test.save()
        values = (domain, batch_request, batch_test)
        batch_domain = BatchDomain(**{k: v for k, v in zip(keys, values)})
        batch_domain.save()

    batch_request.refresh_from_db()
    if batch_request.status != BatchRequestStatus.cancelled:
        batch_request.status = BatchRequestStatus.live
    batch_request.save()


@transaction.atomic
def delete_batch_request(batch_request):
    """
    Remove the batch request together with all the batch related tables'
    entries.

    .. note:: It DOES NOT remove any entries from the vanilla tables.

    """
    batch_domains = batch_request.domains.all()
    for batch_domain in batch_domains:
        batch_domain.get_batch_test().delete()
        batch_domain.delete()
    batch_request.delete()


def create_batch_user(username, name, organization, email):
    """
    Create a batch user in the DB.

    """
    user = BatchUser(
        username=username, name=name, organization=organization, email=email)
    user.save()
    return user


def register_request(request, *args, **kwargs):
    try:
        json_req = json.loads(request.body.decode('utf-8'))
        request_type = json_req.get('type')
        if not request_type:
            return bad_client_request_response(
                "'type' is missing from the request.")

        domains = json_req.get('domains')
        if not domains:
            return bad_client_request_response(
                "'domains' is missing from the request.")
        name = json_req.get('name', 'no-name')
    except Exception:
        return general_server_error("Problem parsing domains.")

    if request_type.lower() == "web":
        return register_batch_request(
            request, kwargs['batch_user'], BatchRequestType.web, name, domains)

    elif request_type.lower() == "mail":
        return register_batch_request(
            request, kwargs['batch_user'], BatchRequestType.mail, name, domains)

    else:
        return bad_client_request_response(
            "'type' is not one of the expected values.")


def register_batch_request(request, user, test_type, name, domains):
    batch_request = BatchRequest(user=user, name=name, type=test_type)
    batch_request.save()

    # Sort domains and shuffle them. Cheap countermeasure to avoid testing the
    # same end-systems simultaneously.
    domains = sorted(set(domains))
    random.shuffle(domains)
    batch_async_register.delay(
        batch_request=batch_request, test_type=test_type, domains=domains)

    request_dict = batch_request.to_api_dict()
    return api_response({"request": request_dict})


def list_requests(request, *args, **kwargs):
    user = kwargs['batch_user']
    try:
        limit = int(request.GET.get('limit'))
        if limit == 0:
            limit = None
    except TypeError:
        limit = 10
    provide_progress = request.GET.get('progress')
    provide_progress = provide_progress and provide_progress.lower() == 'true'

    batch_requests = (
        BatchRequest.objects.filter(user=user).order_by('-id')[:limit])
    batch_info = []
    for batch_request in batch_requests:
        request_dict = batch_request.to_api_dict()
        if provide_progress:
            total_domains = BatchDomain.objects.filter(
                batch_request=batch_request).count()
            finished_domains = BatchDomain.objects.filter(
                batch_request=batch_request,
                status__in=(BatchDomainStatus.done,
                            BatchDomainStatus.error)).count()
            request_dict['progress'] = f"{finished_domains}/{total_domains}"
            request_dict['num_domains'] = total_domains
        batch_info.append(request_dict)
        # We don't need a link to the results, the API is pretty clean now
        #        results="{}{}".format(
        #            get_site_url(request),
        #            reverse(
        #                'batch_results', args=(batch_request.request_id, ))),
    return api_response({"requests": batch_info})


@transaction.atomic
def patch_request(request, batch_request):
    try:
        json_req = json.loads(request.body.decode('utf-8'))
        request_status = json_req.get('status')
        if not request_status:
            return bad_client_request_response(
                "'status' is missing from the request.")
        cancel_value = BatchRequestStatus.cancelled.name.lower()
        if request_status.lower() != cancel_value:
            return bad_client_request_response(
                "'status' does not have one of the supported values: "
                f"['{cancel_value}'].")
        batch_request.status = BatchRequestStatus.cancelled
        batch_request.save()
        BatchDomain.objects.filter(batch_request=batch_request).update(
            status=BatchDomainStatus.cancelled)
        return api_response({"request": batch_request.to_api_dict()})

    except Exception:
        return general_server_error("Problem cancelling the batch request.")


def get_request(request, batch_request):
    provide_progress = request.GET.get('progress')
    provide_progress = provide_progress and provide_progress.lower() == 'true'
    res = {"request": batch_request.to_api_dict()}
    if provide_progress:
        total_domains = BatchDomain.objects.filter(
            batch_request=batch_request).count()
        finished_domains = BatchDomain.objects.filter(
            batch_request=batch_request,
            status__in=(BatchDomainStatus.done,
                        BatchDomainStatus.error)).count()
        res['request']['progress'] = f"{finished_domains}/{total_domains}"
        res['request']['num_domains'] = total_domains
    return api_response(res)
