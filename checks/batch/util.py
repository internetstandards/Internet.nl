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
from django.urls import reverse
from django.db import transaction
from django.utils import timezone

from . import BATCH_API_FULL_VERSION, REPORT_METADATA_WEB_MAP
from . import REPORT_METADATA_MAIL_MAP, BATCH_API_CATEGORY_TO_PROBE_NAME
from . import BATCH_PROBE_NAME_TO_API_CATEGORY
from .responses import api_response, unauthorised_response
from .responses import bad_client_request_response
from .responses import general_server_error_response
from .custom_results import CUSTOM_RESULTS_MAP
from .. import batch_shared_task, redis_id
from ..probes import batch_webprobes, batch_mailprobes
from ..models import BatchUser, BatchRequestType, BatchDomainStatus
from ..models import BatchWebTest, BatchMailTest
from ..models import BatchDomain, BatchRequestStatus, BatchRequest
from ..models import DomainTestReport
from ..scoring import STATUSES_API_TEXT_MAP
from ..views.shared import pretty_domain_name, validate_dname


verdict_regex = re.compile(
    r'^detail (?:[^\s]+ [^\s]+ [^\s]+ )?verdict ([^\s]+)$',
    flags=re.I)


class APIMetadata:
    """
    Class to manage the API metadata.

    """
    @staticmethod
    def _cache_metadata(metadata):
        cache_id = redis_id.batch_metadata.id
        cache.set(cache_id, metadata['name_map'], None)
        del metadata['name_map']

        cache_id = redis_id.report_metadata.id
        cache.set(cache_id, metadata, None)

    @staticmethod
    def _gather_status_verdict_map(item, data, name_map, category):
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
            status = STATUSES_API_TEXT_MAP[subtest.status]
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

    @classmethod
    def get_report_metadata(cls):
        cache_id = redis_id.report_metadata.id
        if not cache.get(cache_id, None):
            cls.build_metadata()
        return cache.get(cache_id, None)

    @classmethod
    def get_batch_metadata(cls):
        cache_id = redis_id.report_metadata.id
        if not cache.get(cache_id, None):
            cls.build_metadata()
        return cache.get(cache_id, None)

    @classmethod
    def _parse_report_item(
            cls, item, hierarchy, data, name_map, probeset, category=None):
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
                cls._parse_report_item(
                    child, hier['children'], data, name_map, probeset,
                    category)
        hierarchy.append(hier)
        if item['type'] != "test":
            return
        cls._gather_status_verdict_map(item, data, name_map, category)

    @classmethod
    def build_metadata(cls):
        res = {}
        res['data'] = {}
        res['hierarchy'] = {
            'web': [],
            'mail': []
        }
        res['name_map'] = {
            'web': {},
            'mail': {}
        }
        for item in REPORT_METADATA_WEB_MAP:
            cls._parse_report_item(
                item, res['hierarchy']['web'], res['data'],
                res['name_map']['web'], batch_webprobes)

        for item in REPORT_METADATA_MAIL_MAP:
            cls._parse_report_item(
                item, res['hierarchy']['mail'], res['data'],
                res['name_map']['mail'], batch_mailprobes)

        cls._cache_metadata(res)


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


@contextmanager
def memcache_lock(lock_id, lock_duration=60*5):
    """
    Simple cache lock to keep celerybeat tasks from running before the previous
    execution has not finished yet.

    Also used for simple tasks that may be triggered more than one for the same
    task.

    .. note:: Mostly as documented in the celery documentation.

    """
    if lock_duration is None:
        # Locking something indefinitely is not a good idea;
        # give a high duration instead.
        lock_duration = 60*60*12  # half a day

    timeout_at = monotonic() + lock_duration - 3
    # cache.add fails if the key already exists
    status = cache.add(lock_id, True, lock_duration)
    try:
        yield status
    finally:
        # memcache delete is very slow, but we have to use it to take
        # advantage of using add() for atomic locking
        if status and monotonic() < timeout_at:
            # don't release the lock if we exceeded the timeout
            # to lessen the chance of releasing an expired lock
            # owned by someone else
            # also don't release the lock if we didn't acquire it
            cache.delete(lock_id)


def get_active_custom_result_instances():
    return [
        CUSTOM_RESULTS_MAP[r] for r, active
        in settings.BATCH_API_CUSTOM_RESULTS.items() if active
    ]


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
                del results
                results = gather_batch_results_technical(user, batch_request, site_url)
                save_batch_results_to_file(user, batch_request, results, technical=True)


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

    custom_instances = get_active_custom_result_instances()
    probes, url_name, url_arg, related_fields, prefetch_fields, name_map = (
        get_batch_request_info(batch_request, False, custom_instances))
    dom_results = {}

    batch_domains_q = batch_request.domains.all().select_related(*related_fields)
    if prefetch_fields:
        batch_domains_q = batch_domains_q.prefetch_related(*prefetch_fields)
    for batch_domain in batch_domains_q:
        result = {}
        domain_name_idna = pretty_domain_name(batch_domain.domain)
        dom_results[domain_name_idna] = result
        if batch_domain.status == BatchDomainStatus.error:
            result['status'] = "error"
            continue
        result['status'] = "ok"

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
            probe_full_name = probe.prefix + probe.name
            category = BATCH_PROBE_NAME_TO_API_CATEGORY[probe_full_name]
            model = getattr(report_table, probe.name)
            _, _, verdict, text_verdict = probe.get_scores_and_verdict(model)
            categories[category] = {
                "verdict": text_verdict,
                "status": verdict
            }

            report = model.report
            for subtest, sub_data in report.items():
                if name_map.get(subtest):
                    status = STATUSES_API_TEXT_MAP[sub_data['status']]
                    verdict = (
                        verdict_regex.fullmatch(sub_data['verdict']).group(1))
                    tests[name_map[subtest]] = {
                        "status": status,
                        "verdict": verdict,
                    }

        for custom_instance in custom_instances:
            custom_data = custom_instance.get_data(report_table)
            if custom_data is not None:
                customs[custom_instance.name] = custom_data

    data['domains'] = dom_results
    return data


def get_batch_request_info(batch_request, prefetch_related, custom_instances):
    if batch_request.type is BatchRequestType.web:
        webtest = True
        probes = batch_webprobes.getset()
        url_name = 'webtest_results'
        url_arg = ['site']
        related_testset = 'webtest'
        name_map = cache.get(redis_id.batch_metadata.id)['web']
    else:
        webtest = False
        probes = batch_mailprobes.getset()
        url_name = 'mailtest_results'
        url_arg = []
        related_testset = 'mailtest'
        name_map = cache.get(redis_id.batch_metadata.id)['mail']

    # Quering for the related rows upfront minimizes further DB queries and
    # gives ~33% boost to performance.
    related_fields = set()
    prefetch_fields = set()
    for probe in probes:
        inter_table_relation = f'{related_testset}__report__{probe.name}'
        related_fields.add(inter_table_relation)
        if prefetch_related:
            # Here we add the OneToMany relations (if needed) that cannot be
            # queried with one complex query as with the related_fields above
            # (OneToOne relation).
            # For each such connection an additional query will be issued
            # regardless of the number of actual items in the DB.
            if webtest:
                if probe.name == 'tls':
                    prefetch_fields.add(f'{inter_table_relation}__webtestset')
                elif probe.name == 'ipv6':
                    prefetch_fields.add(f'{inter_table_relation}__nsdomains')
                    prefetch_fields.add(f'{inter_table_relation}__webdomains')
                elif probe.name == 'appsecpriv':
                    prefetch_fields.add(f'{inter_table_relation}__webtestset')
            else:
                if probe.name == 'tls':
                    prefetch_fields.add(f'{inter_table_relation}__testset')
                elif probe.name == 'ipv6':
                    prefetch_fields.add(f'{inter_table_relation}__nsdomains')
                    prefetch_fields.add(f'{inter_table_relation}__mxdomains')
                elif probe.name == 'dnssec':
                    prefetch_fields.add(f'{inter_table_relation}__testset')

    for custom_instance in custom_instances:
        custom_prefetch = custom_instance.related_db_tables(batch_request.type)
        if custom_prefetch:
            prefetch_fields.update(
                {f'{related_testset}__report__{c}' for c in custom_prefetch})

    return probes, url_name, url_arg, related_fields, prefetch_fields, name_map


class DomainTechnicalResults:
    """
    Class to group all the functions needed for generating the technical
    results endpoint together.

    """

    @classmethod
    def _get_addresses_info(cls, domain_table):
        addr4 = []
        addr6 = []
        res = {'ipv4': {'addresses': addr4}, 'ipv6': {'addresses': addr6}}
        for addr in domain_table.v4_good:
            addr4.append({'address': addr, 'reachable': True})
        for addr in domain_table.v4_bad:
            addr4.append({'address': addr, 'reachable': False})
        for addr in domain_table.v6_good:
            addr6.append({'address': addr, 'reachable': True})
        for addr in domain_table.v6_bad:
            addr6.append({'address': addr, 'reachable': False})
        return res

    @classmethod
    def _get_web_tls_info(cls, dttls, report_table):
        res = {
            'https_enabled': dttls.tls_enabled,
            'server_reachable': dttls.server_reachable,
            'tested_address': dttls.domain,
        }
        if dttls.tls_enabled and dttls.server_reachable:
            res['details'] = dttls.get_web_api_details()
            for dtappsecpriv in report_table.appsecpriv.webtestset.all():
                if dtappsecpriv.domain != dttls.domain:
                    continue
                res['details'].update(dtappsecpriv.get_web_api_details())
        return res

    @classmethod
    def _get_mail_tls_info(cls, dttls):
        res = {
            'starttls_enabled': dttls.tls_enabled,
            'server_reachable': dttls.server_reachable,
            'server_testable': not dttls.could_not_test_smtp_starttls
        }
        if (dttls.tls_enabled and dttls.server_reachable
                and not dttls.could_not_test_smtp_starttls):
            res['details'] = dttls.get_mail_api_details()
        return res

    @classmethod
    def _get_web_domain(cls, report_table):
        dtdnssec = report_table.dnssec
        return {'dnssec': {'status': dtdnssec.status.name}}

    @classmethod
    def _get_mail_domain(cls, report_table):
        res = {}

        # dnssec
        for dtdnssec in report_table.dnssec.testset.all():
            # Cheap way to see if the result is for the domain
            # or one of the mailservers.
            if not dtdnssec.domain.endswith("."):
                res['dnssec'] = {'status': dtdnssec.status.name}

        auth = report_table.auth
        # dkim
        res['dkim'] = {'discovered': auth.dkim_available}

        # dmarc
        dmarc = {'records': auth.dmarc_record}
        if auth.dmarc_available:
            dmarc['policy_status'] = auth.dmarc_policy_status.name
        res['dmarc'] = dmarc

        # spf
        spf = {
            'records': auth.spf_record,
            'discovered_records_bad': auth.spf_policy_records
        }
        if auth.spf_available:
            spf['policy_status'] = auth.spf_policy_status.name
        res['spf'] = spf

        return res

    @classmethod
    def _get_web_nameservers(cls, report_table):
        nameservers = {}
        nsdomains = report_table.ipv6.nsdomains.all()
        for nsdomain in nsdomains:
            nameservers[nsdomain.domain] = cls._get_addresses_info(nsdomain)
        return nameservers

    @classmethod
    def _get_mail_nameservers(cls, report_table):
        nameservers = {}
        nsdomains = report_table.ipv6.nsdomains.all()
        for nsdomain in nsdomains:
            nameservers[nsdomain.domain] = cls._get_addresses_info(nsdomain)
        return nameservers

    @classmethod
    def _get_web_webservers(cls, report_table):
        webservers = {}

        distance = report_table.ipv6.web_simhash_distance
        if (distance and distance >= 0 and distance <= 100):
            ip_similarity = distance <= settings.SIMHASH_MAX
            webservers['ip_similarity'] = ip_similarity

        webdomain = report_table.ipv6.webdomains.all()[0]
        webservers.update(cls._get_addresses_info(webdomain))

        for dttls in report_table.tls.webtestset.all():
            info = cls._get_web_tls_info(dttls, report_table)
            if any(filter(
                    lambda x: x['address'] == info['tested_address'],
                    webservers['ipv4']['addresses'])):
                webservers['ipv4'].update(info)
            else:
                webservers['ipv6'].update(info)

        return webservers

    @classmethod
    def _get_mail_mailservers(cls, report_table):
        mailservers = {}
        for mxdomain in report_table.ipv6.mxdomains.all():
            mailserver = {}
            mailservers[mxdomain.domain] = mailserver
            mailserver['addresses'] = cls._get_addresses_info(mxdomain)

        for dtdnssec in report_table.dnssec.testset.all():
            # Cheap way to see if the result is for the domain
            # or one of the mailservers.
            if not dtdnssec.domain.endswith("."):
                continue

            # Old results where not sharing the same MXs on all tests.
            # This will result in partial details between the tests here.
            if dtdnssec.domain not in mailservers:
                mailservers[dtdnssec.domain] = {}
            mailservers[dtdnssec.domain]['dnssec'] = {
                'status': dtdnssec.status.name}

        for dttls in report_table.tls.testset.all():
            # Old results where not sharing the same MXs on all tests.
            # This will result in partial details between the tests here.
            if dttls.domain not in mailservers:
                mailservers[dttls.domain] = {}

            info = cls._get_mail_tls_info(dttls)
            mailservers[dttls.domain].update(info)

        return mailservers

    @classmethod
    def _get_web_details(cls, report_table):
        details = {}
        details['domain'] = cls._get_web_domain(report_table)
        details['nameservers'] = cls._get_web_nameservers(report_table)
        details['webservers'] = cls._get_web_webservers(report_table)
        return details

    @classmethod
    def _get_mail_details(cls, report_table):
        details = {}
        details['domain'] = cls._get_mail_domain(report_table)
        details['nameservers'] = cls._get_mail_nameservers(report_table)
        details['receiving_mailservers'] = cls._get_mail_mailservers(report_table)
        return details

    @classmethod
    def fill_result(cls, report_table, result):
        """
        Gathers all the available technical details from `report_table` and
        updates `result` with the data.

        """
        if isinstance(report_table, DomainTestReport):
            details = cls._get_web_details(report_table)
        else:
            details = cls._get_mail_details(report_table)
        result.update(details)


def gather_batch_results_technical(user, batch_request, site_url):
    """
    Gather all the technical results for the batch request and return them in a
    dictionary that will be eventually converted to JSON for the API answer.

    """
    data = {
        "api_version": BATCH_API_FULL_VERSION,
        "request": batch_request.to_api_dict()
    }
    # Technically the status is still generating.
    data['request']['status'] = "done"

    probes, url_name, url_arg, related_fields, prefetch_fields, name_map = (
        get_batch_request_info(batch_request, True, []))
    dom_results = {}

    batch_domains_q = batch_request.domains.all().select_related(*related_fields)
    if prefetch_fields:
        batch_domains_q = batch_domains_q.prefetch_related(*prefetch_fields)
    for batch_domain in batch_domains_q:
        result = {}
        domain_name_idna = pretty_domain_name(batch_domain.domain)
        dom_results[domain_name_idna] = result
        if batch_domain.status == BatchDomainStatus.error:
            result['status'] = "error"
            continue
        result['status'] = "ok"

        batch_test = batch_domain.get_batch_test()
        report_table = batch_test.report
        DomainTechnicalResults.fill_result(report_table, result)

    data['domains'] = dom_results
    return data


def save_batch_results_to_file(user, batch_request, results, technical=False):
    """
    Save results to file using the Django's ORM utilities.

    """
    technical_text = '-technical' if technical else ''
    filename = '{}-{}-{}{}.json'.format(
        user.username, batch_request.type.label, batch_request.id,
        technical_text)
    batch_request.get_report_file(technical).save(
        filename, ContentFile(json.dumps(results)))


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


def create_batch_user(username, name, organization, email):
    """
    Create a batch user in the DB.

    """
    try:
        user = BatchUser.objects.get(username=username)
        return None
    except BatchUser.DoesNotExist:
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
        if not domains or type(domains) is not list:
            return bad_client_request_response(
                "'domains' is missing from the request.")
        name = json_req.get('name', 'no-name')
    except Exception:
        return general_server_error_response("Problem parsing domains.")

    if request_type.lower() == "web":
        return register_batch_request(
            request, kwargs['batch_user'], BatchRequestType.web, name,
            domains)

    elif request_type.lower() == "mail":
        return register_batch_request(
            request, kwargs['batch_user'], BatchRequestType.mail, name,
            domains)

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
        return general_server_error_response(
            "Problem cancelling the batch request.")


def get_request(request, batch_request, user):
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
    if (batch_request.status == BatchRequestStatus.done
            and not batch_request.has_report_file()):
        batch_async_generate_results.delay(
            user=user,
            batch_request=batch_request,
            site_url=get_site_url(request))
    return api_response(res)
