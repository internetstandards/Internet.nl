# Copyright: 2022, ECP, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
import inspect
import json
import random
import re
from collections import defaultdict
from contextlib import contextmanager
from functools import wraps
from ipaddress import ip_address
from json.decoder import JSONDecodeError
from time import monotonic
from typing import Optional

from django.conf import settings
from django.core.cache import cache
from django.core.files.base import ContentFile
from django.db import transaction
from django.http import JsonResponse
from django.urls import reverse
from django.utils import timezone

from checks.models import (
    BatchDomain,
    BatchDomainStatus,
    BatchMailTest,
    BatchRequest,
    BatchRequestStatus,
    BatchRequestType,
    BatchUser,
    BatchWebTest,
    DomainTestReport,
)
from checks.probes import batch_mailprobes, batch_webprobes
from checks.scoring import STATUSES_API_TEXT_MAP
from interface import batch_shared_task, redis_id
from interface.batch import (
    BATCH_API_CATEGORY_TO_PROBE_NAME,
    BATCH_API_FULL_VERSION,
    BATCH_PROBE_NAME_TO_API_CATEGORY,
    REPORT_METADATA_MAIL_MAP,
    REPORT_METADATA_WEB_MAP,
)
from interface.batch.custom_results import CUSTOM_RESULTS_MAP
from interface.batch.responses import (
    api_response,
    bad_client_request_response,
    general_server_error_response,
    unauthorised_response,
)
from interface.views.shared import pretty_domain_name, validate_dname
from internetnl import log
from checks.tasks.routing import BGPSourceUnavailableError, NoRoutesError

verdict_regex = re.compile(r"^detail (?:[^\s]+ [^\s]+ [^\s]+ )?verdict ([^\s]+)$", flags=re.I)


class APIMetadata:
    """
    Class to manage the API metadata.

    """

    @staticmethod
    def _cache_metadata(metadata):
        cache_id = redis_id.batch_metadata.id
        cache.set(cache_id, metadata["name_map"], None)
        del metadata["name_map"]

        cache_id = redis_id.report_metadata.id
        cache.set(cache_id, metadata, None)

    @staticmethod
    def _gather_status_verdict_map(item, data, name_map, category):
        # Continue here for test items.
        name_map[item["name_on_report"]] = item["name"]

        status_verdict_map = defaultdict(set)

        testname = item["name_on_report"]
        subtest = category.subtests[testname]

        result_methods = [
            method[1]
            for method in inspect.getmembers(subtest, predicate=inspect.ismethod)
            if method[0].startswith("result_")
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
            if fullverdict in ("detail verdict not-tested", "detail verdict could-not-test"):
                verdict = fullverdict
            else:
                verdict = verdict_regex.fullmatch(subtest.verdict).group(1)
            status_verdict_map[status].add(verdict)
        # Add the default status/verdict for each test.
        status_verdict_map["not_tested"].add("detail verdict not-tested")
        # Make it JSON serialisable.
        data[item["name"]]["status_verdict_map"] = {
            status: list(verdicts) for status, verdicts in status_verdict_map.items()
        }

    @classmethod
    def get_report_metadata(cls):
        cache_id = redis_id.report_metadata.id
        if not cache.get(cache_id, None):
            cls.build_metadata()
        data = cache.get(cache_id, None)
        return data

    @classmethod
    def get_batch_metadata(cls):
        cache_id = redis_id.report_metadata.id
        if not cache.get(cache_id, None):
            cls.build_metadata()
        data = cache.get(cache_id, None)
        return data

    @classmethod
    def _parse_report_item(cls, item, hierarchy, data, name_map, probeset, category=None):
        data[item["name"]] = {
            "type": item["type"],
            "translation_key": item["translation_key"],
        }
        hier = {"name": item["name"]}

        if "children" in item:
            hier["children"] = []

            # Initialise the category if visiting a category's children.
            if item["type"] == "category":
                probe_name = BATCH_API_CATEGORY_TO_PROBE_NAME[item["name"]]
                category = probeset[probe_name].category()

            for child in item["children"]:
                cls._parse_report_item(child, hier["children"], data, name_map, probeset, category)
        hierarchy.append(hier)
        if item["type"] != "test":
            return
        cls._gather_status_verdict_map(item, data, name_map, category)

    @classmethod
    def build_metadata(cls):
        res = {}
        res["data"] = {}
        res["hierarchy"] = {"web": [], "mail": []}
        res["name_map"] = {"web": {}, "mail": {}}
        for item in REPORT_METADATA_WEB_MAP:
            cls._parse_report_item(item, res["hierarchy"]["web"], res["data"], res["name_map"]["web"], batch_webprobes)

        for item in REPORT_METADATA_MAIL_MAP:
            cls._parse_report_item(
                item, res["hierarchy"]["mail"], res["data"], res["name_map"]["mail"], batch_mailprobes
            )

        cls._cache_metadata(res)


def get_site_url(request):
    """
    Compose the url that the user used to connect to the API.

    """
    return f"{request.scheme}://{request.get_host()}"


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
        kwargs["batch_user"] = user
        return function(request, *args, **kwargs)

    return wrap


def get_user_from_request(request):
    """
    If the user that made the request is a legitimate batch user (exists in the
    DB) return the relevant user object from the DB.

    """
    username = request.META.get("REMOTE_USER") or request.headers.get("remote-user")
    if not username:
        username = getattr(settings, "BATCH_TEST_USER", None)
    user, created = BatchUser.objects.get_or_create(username=username)
    if created:
        log.debug("Created new user %s in database", username)
    return user


@contextmanager
def memcache_lock(lock_id, lock_duration=60 * 5):
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
        lock_duration = 60 * 60 * 12  # half a day

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
    return [CUSTOM_RESULTS_MAP[r] for r, active in settings.BATCH_API_CUSTOM_RESULTS.items() if active]


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
        user = kwargs["user"]
        batch_request = kwargs["batch_request"]
        lock_id = lock_id_name.format(user.username, batch_request.request_id)
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

    request_lock_id = redis_id.batch_results_request_lock.id.format(batch_request.request_id)
    cache.delete(request_lock_id)


def gather_batch_results(user, batch_request, site_url):
    """
    Gather all the results for the batch request and return them in a
    dictionary that will be eventually converted to JSON for the API answer.

    """
    data = {"api_version": BATCH_API_FULL_VERSION, "request": batch_request.to_api_dict()}
    # Technically the status is still generating.
    data["request"]["status"] = "done"

    custom_instances = get_active_custom_result_instances()
    probes, url_name, url_arg, related_fields, prefetch_fields, name_map = get_batch_request_info(
        batch_request, False, custom_instances
    )
    dom_results = {}

    batch_domains_q = batch_request.domains.all().select_related(*related_fields)
    if prefetch_fields:
        batch_domains_q = batch_domains_q.prefetch_related(*prefetch_fields)
    for batch_domain in batch_domains_q:
        result = {}
        domain_name_idna = pretty_domain_name(batch_domain.domain)
        dom_results[domain_name_idna] = result
        if batch_domain.status == BatchDomainStatus.error:
            result["status"] = "error"
            continue
        result["status"] = "ok"

        batch_test = batch_domain.get_batch_test()
        report_table = batch_test.report
        score = report_table.score

        args = url_arg + [batch_domain.domain, report_table.id]
        result["report"] = {"url": f"{site_url}{reverse(url_name, args=args)}"}
        result["scoring"] = {"percentage": score}

        tests = {}
        categories = {}
        customs = {}
        result["results"] = {"categories": categories, "tests": tests, "custom": customs}

        for probe in probes:
            probe_full_name = probe.prefix + probe.name
            category = BATCH_PROBE_NAME_TO_API_CATEGORY[probe_full_name]
            model = getattr(report_table, probe.name)
            _, _, verdict, text_verdict = probe.get_scores_and_verdict(model)
            categories[category] = {"verdict": text_verdict, "status": verdict}

            report = model.report
            for subtest, sub_data in report.items():
                if name_map.get(subtest):
                    status = STATUSES_API_TEXT_MAP[sub_data["status"]]
                    verdict = verdict_regex.fullmatch(sub_data["verdict"]).group(1)
                    tests[name_map[subtest]] = {
                        "status": status,
                        "verdict": verdict,
                    }

        for custom_instance in custom_instances:
            custom_data = custom_instance.get_data(report_table)
            if custom_data is not None:
                customs[custom_instance.name] = custom_data

    data["domains"] = dom_results
    return data


def get_batch_request_info(batch_request, prefetch_related, custom_instances):
    if batch_request.type is BatchRequestType.web:
        # This expects 'batch:name_map_metadata' to be set in redis. But where is that set?
        webtest = True
        probes = batch_webprobes.getset()
        url_name = "webtest_results"
        url_arg = ["site"]
        related_testset = "webtest"
        log.debug("Getting redis metadata from cache with id: %s", redis_id.batch_metadata.id)
        log.debug("Metadata information: %s", redis_id.batch_metadata)
        cached_data = cache.get(redis_id.batch_metadata.id)
        log.debug("Cached data retrieved: %s", cached_data)
        # This can be none... has it not been registered correctly?
        name_map = cached_data["web"]
    else:
        webtest = False
        probes = batch_mailprobes.getset()
        url_name = "mailtest_results"
        url_arg = []
        related_testset = "mailtest"
        name_map = cache.get(redis_id.batch_metadata.id)["mail"]

    # Quering for the related rows upfront minimizes further DB queries and
    # gives ~33% boost to performance.
    related_fields = set()
    prefetch_fields = set()
    for probe in probes:
        inter_table_relation = f"{related_testset}__report__{probe.name}"
        related_fields.add(inter_table_relation)
        if prefetch_related:
            # Here we add the OneToMany relations (if needed) that cannot be
            # queried with one complex query as with the related_fields above
            # (OneToOne relation).
            # For each such connection an additional query will be issued
            # regardless of the number of actual items in the DB.
            if webtest:
                if probe.name == "tls":
                    prefetch_fields.add(f"{inter_table_relation}__webtestset")
                elif probe.name == "ipv6":
                    prefetch_fields.add(f"{inter_table_relation}__nsdomains")
                    prefetch_fields.add(f"{inter_table_relation}__webdomains")
                elif probe.name == "appsecpriv":
                    prefetch_fields.add(f"{inter_table_relation}__webtestset")
                elif probe.name == "rpki":
                    prefetch_fields.add(f"{inter_table_relation}__nshosts")
                    prefetch_fields.add(f"{inter_table_relation}__webhosts")
            else:
                if probe.name == "tls":
                    prefetch_fields.add(f"{inter_table_relation}__testset")
                elif probe.name == "ipv6":
                    prefetch_fields.add(f"{inter_table_relation}__nsdomains")
                    prefetch_fields.add(f"{inter_table_relation}__mxdomains")
                elif probe.name == "dnssec":
                    prefetch_fields.add(f"{inter_table_relation}__testset")
                elif probe.name == "rpki":
                    prefetch_fields.add(f"{inter_table_relation}__nshosts")
                    prefetch_fields.add(f"{inter_table_relation}__mxhosts")

    for custom_instance in custom_instances:
        custom_prefetch = custom_instance.related_db_tables(batch_request.type)
        if custom_prefetch:
            prefetch_fields.update({f"{related_testset}__report__{c}" for c in custom_prefetch})

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
        res = {"ipv4": {"addresses": addr4}, "ipv6": {"addresses": addr6}}
        for addr in domain_table.v4_good:
            addr4.append({"address": addr, "reachable": True})
        for addr in domain_table.v4_bad:
            addr4.append({"address": addr, "reachable": False})
        for addr in domain_table.v6_good:
            addr6.append({"address": addr, "reachable": True})
        for addr in domain_table.v6_bad:
            addr6.append({"address": addr, "reachable": False})
        return res

    @classmethod
    def _add_routing_info(cls, domain_table, addresses_info):
        if not addresses_info:
            addresses_info = {"ipv4": {"addresses": []}, "ipv6": {"addresses": []}}

        routing_info = cls._get_routing_info(domain_table)

        addr = {}
        addr[4] = addresses_info["ipv4"]["addresses"]
        addr[6] = addresses_info["ipv6"]["addresses"]

        for addr_list in addr.values():
            for entry in addr_list:
                ip = entry["address"]
                if ip in routing_info:
                    entry["routing"] = routing_info[ip]
                    del routing_info[ip]

        # ip addresses not yet present in address_info
        for ip, routes in routing_info.items():
            version = ip_address(ip).version

            addr[version].append({"address": ip, "routing": routes})

        return addresses_info

    @classmethod
    def _get_routing_info(cls, domain_table):
        def pp_validity(v):
            state = v["state"]
            reason = v["reason"]

            return f"{state} ({reason})" if state == "invalid" else state

        addr = defaultdict(list)

        for r in domain_table.routing:
            ip = r["ip"]
            routes = []
            for route, validity in r["validity"].items():
                if BGPSourceUnavailableError.__name__ in r["errors"] or NoRoutesError.__name__ in r["errors"]:
                    continue

                origin, prefix = route
                routes.append({"origin": f"AS{origin}", "route": prefix, "rov_state": pp_validity(validity)})

            addr[ip].extend(routes)

        return addr

    @classmethod
    def _get_web_tls_info(cls, dttls, report_table):
        res = {
            "https_enabled": dttls.tls_enabled,
            "server_reachable": dttls.server_reachable,
            "tested_address": dttls.domain,
        }
        if dttls.tls_enabled and dttls.server_reachable:
            res["details"] = dttls.get_web_api_details()
            for dtappsecpriv in report_table.appsecpriv.webtestset.all():
                if dtappsecpriv.domain != dttls.domain:
                    continue
                res["details"].update(dtappsecpriv.get_web_api_details())
        return res

    @classmethod
    def _get_mail_tls_info(cls, dttls):
        res = {
            "starttls_enabled": dttls.tls_enabled,
            "server_reachable": dttls.server_reachable,
            "server_testable": not dttls.could_not_test_smtp_starttls,
        }
        if dttls.tls_enabled and dttls.server_reachable and not dttls.could_not_test_smtp_starttls:
            res["details"] = dttls.get_mail_api_details()
        return res

    @classmethod
    def _get_web_domain(cls, report_table):
        dtdnssec = report_table.dnssec
        # In case the test did not run, as it was not flagged to run:
        if not dtdnssec:
            return {"dnssec": {"status": "not tested"}}

        return {"dnssec": {"status": dtdnssec.status.name}}

    @classmethod
    def _get_mail_domain(cls, report_table):
        res = {}

        if not report_table.dnssec:
            return {}

        # dnssec
        for dtdnssec in report_table.dnssec.testset.all():
            # Cheap way to see if the result is for the domain
            # or one of the mailservers.
            if not dtdnssec.domain.endswith("."):
                res["dnssec"] = {"status": dtdnssec.status.name}

        auth = report_table.auth
        # dkim
        res["dkim"] = {"discovered": auth.dkim_available}

        # dmarc
        dmarc = {"records": auth.dmarc_record, "record_org_domain": auth.dmarc_record_org_domain}
        if auth.dmarc_available:
            dmarc["policy_status"] = auth.dmarc_policy_status.name
        res["dmarc"] = dmarc

        # spf
        spf = {"records": auth.spf_record, "discovered_records_bad": auth.spf_policy_records}
        if auth.spf_available:
            spf["policy_status"] = auth.spf_policy_status.name
        res["spf"] = spf

        return res

    @classmethod
    def _get_web_nameservers(cls, report_table):
        nameservers = {}

        if report_table.ipv6:
            for nsdomain in report_table.ipv6.nsdomains.all():
                nameservers[nsdomain.domain] = cls._get_addresses_info(nsdomain)

        if report_table.rpki:
            for nshost in report_table.rpki.nshosts.all():
                nameservers[nshost.host] = cls._add_routing_info(nshost, nameservers.get(nshost.host, None))

        return nameservers

    @classmethod
    def _get_mail_nameservers(cls, report_table):
        nameservers = {}

        if report_table.ipv6:
            for nsdomain in report_table.ipv6.nsdomains.all():
                nameservers[nsdomain.domain] = cls._get_addresses_info(nsdomain)

        if report_table.rpki:
            for nshost in report_table.rpki.nshosts.all():
                nameservers[nshost.host] = cls._add_routing_info(nshost, nameservers.get(nshost.host, None))

        return nameservers

    @classmethod
    def _get_mail_mx_nameservers(cls, report_table):
        nameservers = {}

        if report_table.rpki:
            for mxnshost in report_table.rpki.mxnshosts.all():
                nameservers[mxnshost.host] = cls._get_routing_info(mxnshost)

        return nameservers

    @classmethod
    def _get_web_webservers(cls, report_table):
        webservers = {}

        distance = report_table.ipv6.web_simhash_distance
        if distance and distance >= 0 and distance <= 100:
            ip_similarity = distance <= settings.SIMHASH_MAX
            webservers["ip_similarity"] = ip_similarity

        # always loops once, guaranteed to exist
        for webdomain in report_table.ipv6.webdomains.all():
            webservers.update(cls._get_addresses_info(webdomain))

        # tls might not have run as it is feature flagged:
        if not report_table.tls:
            return webservers

        # only loops when there's actual A/AAAA records (and routing info)
        if report_table.rpki:
            for webhost in report_table.rpki.webhosts.all():
                webservers = cls._add_routing_info(webhost, webservers)

        for dttls in report_table.tls.webtestset.all():
            info = cls._get_web_tls_info(dttls, report_table)
            if any(filter(lambda x: x["address"] == info["tested_address"], webservers["ipv4"]["addresses"])):
                webservers["ipv4"].update(info)
            else:
                webservers["ipv6"].update(info)

        return webservers

    @classmethod
    def _get_mail_mailservers(cls, report_table):
        mailservers = {}

        if report_table.ipv6:
            for mxdomain in report_table.ipv6.mxdomains.all():
                mailserver = {}
                mailservers[mxdomain.domain] = mailserver
                mailserver["addresses"] = cls._get_addresses_info(mxdomain)

        if report_table.dnssec:
            for dtdnssec in report_table.dnssec.testset.all():
                # Cheap way to see if the result is for the domain
                # or one of the mailservers.
                if not dtdnssec.domain.endswith("."):
                    continue

        if report_table.rpki:
            for mxhost in report_table.rpki.mxhosts.all():
                addr = mailservers.get(mxhost.host, {}).get("addresses")
                mailservers[mxhost.host] = cls._add_routing_info(mxhost, addr)

        if report_table.dnssec:
            for dtdnssec in report_table.dnssec.testset.all():
                # Cheap way to see if the result is for the domain
                # or one of the mailservers.
                if not dtdnssec.domain.endswith("."):
                    continue

                # Old results where not sharing the same MXs on all tests.
                # This will result in partial details between the tests here.
                if dtdnssec.domain not in mailservers:
                    mailservers[dtdnssec.domain] = {}
                mailservers[dtdnssec.domain]["dnssec"] = {"status": dtdnssec.status.name}

        if report_table.tls:
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
        details["domain"] = cls._get_web_domain(report_table)
        details["nameservers"] = cls._get_web_nameservers(report_table)
        details["webservers"] = cls._get_web_webservers(report_table)
        return details

    @classmethod
    def _get_mail_details(cls, report_table):
        details = {}
        details["domain"] = cls._get_mail_domain(report_table)
        details["nameservers"] = cls._get_mail_nameservers(report_table)
        details["mx_nameservers"] = cls._get_mail_mx_nameservers(report_table)
        details["receiving_mailservers"] = cls._get_mail_mailservers(report_table)
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
    data = {"api_version": BATCH_API_FULL_VERSION, "request": batch_request.to_api_dict()}
    # Technically the status is still generating.
    data["request"]["status"] = "done"

    probes, url_name, url_arg, related_fields, prefetch_fields, name_map = get_batch_request_info(
        batch_request, True, []
    )
    dom_results = {}

    batch_domains_q = batch_request.domains.all().select_related(*related_fields)
    if prefetch_fields:
        batch_domains_q = batch_domains_q.prefetch_related(*prefetch_fields)
    for batch_domain in batch_domains_q:
        result = {}
        domain_name_idna = pretty_domain_name(batch_domain.domain)
        dom_results[domain_name_idna] = result
        if batch_domain.status == BatchDomainStatus.error:
            result["status"] = "error"
            continue
        result["status"] = "ok"

        batch_test = batch_domain.get_batch_test()
        report_table = batch_test.report
        DomainTechnicalResults.fill_result(report_table, result)

    data["domains"] = dom_results
    return data


def save_batch_results_to_file(user, batch_request, results, technical=False):
    """
    Save results to file using the Django's ORM utilities.

    """
    technical_text = "-technical" if technical else ""
    filename = f"{user.username}-{batch_request.type.label}-{batch_request.id}{technical_text}.json"
    batch_request.get_report_file(technical).save(filename, ContentFile(json.dumps(results)))


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
        batch_request = kwargs["batch_request"]
        batch_request.refresh_from_db()
        if batch_request.status != BatchRequestStatus.cancelled:
            batch_request.status = BatchRequestStatus.error
        batch_request.finished_date = timezone.now()
        batch_request.save()

    self.on_failure = on_failure

    if test_type is BatchRequestType.web:
        batch_test_model = BatchWebTest
        keys = ("domain", "batch_request", "webtest")
        # Unused because of latency while registering the domains.
        # get_valid_domain = get_valid_domain_web
        get_valid_domain = validate_dname
    else:
        batch_test_model = BatchMailTest
        keys = ("domain", "batch_request", "mailtest")
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


def get_json_data_from_request(request) -> tuple[Optional[Exception], dict]:
    data = {}
    try:
        data = json.loads(request.body.decode("utf-8"))
        return None, data
    except JSONDecodeError as exception_data:
        return exception_data, data
    except Exception as exception_data:
        log.exception(exception_data)
        return exception_data, data


def fields_missing_in_dict(fields: list[str], data: dict) -> list[str]:
    # one dimensional check if the fields are at the root of the dict.
    # builds a list of fields to return and will return those in a bad client response.
    # in case of no missing fields a False is issued.
    missing_fields = []
    for field in fields:
        if field not in data:
            missing_fields.append(field)

    return missing_fields


def missing_fields_error(fields: list[str]) -> JsonResponse:
    messages = [f"'{field}' is missing from the request." for field in fields]
    return bad_client_request_response(",".join(messages))


def register_request(data: dict, *args, **kwargs) -> JsonResponse:
    # todo: this should not return a webserver answer but json. The webserver stuff is just a wrapper.
    missing_fields = fields_missing_in_dict(["type", "domains"], data)
    if missing_fields:
        return missing_fields_error(missing_fields)

    request_type: str = data.get("type")
    request_type = request_type.lower()
    if request_type not in ["web", "mail"]:
        return bad_client_request_response("'type' is not one of the expected values.")

    domains: str = data.get("domains")
    if not domains:
        return bad_client_request_response("Domains are empty.")

    # todo: this is model validation, this should be done in a generic approach, not this patchwork
    name = data.get("name", "no-name")

    # todo: apparently there is always a batch user?
    return register_batch_request(None, kwargs["batch_user"], BatchRequestType[request_type], name, domains)


def register_batch_request(request, user, test_type, name, domains):
    batch_request = BatchRequest(user=user, name=name, type=test_type)
    batch_request.save()

    # Sort domains and shuffle them. Cheap countermeasure to avoid testing the
    # same end-systems simultaneously.
    domains = sorted(set(domains))
    random.shuffle(domains)
    batch_async_register.delay(batch_request=batch_request, test_type=test_type, domains=domains)

    request_dict = batch_request.to_api_dict()
    return api_response({"request": request_dict})


def list_requests(request, *args, **kwargs):
    user = kwargs["batch_user"]
    try:
        limit = int(request.GET.get("limit"))
        if limit == 0:
            limit = None
    except TypeError:
        limit = 10
    provide_progress = request.GET.get("progress")
    provide_progress = provide_progress and provide_progress.lower() == "true"

    batch_requests = BatchRequest.objects.filter(user=user).order_by("-id")[:limit]
    batch_info = []
    for batch_request in batch_requests:
        request_dict = batch_request.to_api_dict()
        if provide_progress:
            total_domains = BatchDomain.objects.filter(batch_request=batch_request).count()
            finished_domains = BatchDomain.objects.filter(
                batch_request=batch_request, status__in=(BatchDomainStatus.done, BatchDomainStatus.error)
            ).count()
            request_dict["progress"] = f"{finished_domains}/{total_domains}"
            request_dict["num_domains"] = total_domains
        batch_info.append(request_dict)
    return api_response({"requests": batch_info})


@transaction.atomic
def patch_request(request, batch_request):
    try:
        json_req = json.loads(request.body.decode("utf-8"))
        request_status = json_req.get("status")
        if not request_status:
            return bad_client_request_response("'status' is missing from the request.")
        cancel_value = BatchRequestStatus.cancelled.name.lower()
        if request_status.lower() != cancel_value:
            return bad_client_request_response(
                "'status' does not have one of the supported values: " f"['{cancel_value}']."
            )
        batch_request.status = BatchRequestStatus.cancelled
        batch_request.save()
        BatchDomain.objects.filter(batch_request=batch_request).update(status=BatchDomainStatus.cancelled)
        return api_response({"request": batch_request.to_api_dict()})
    except JSONDecodeError:
        return bad_client_request_response("Problem parsing json. Did you supply a 'status'?")
    except Exception:
        return general_server_error_response("Problem cancelling the batch request.")


def request_already_generating(request_id):
    """Check the cache and rabbitmq to see if there is a request for generating batch request results."""

    try:
        lock_id = redis_id.batch_results_request_lock.id.format(request_id)
        if cache.get(lock_id):
            log.debug("There is already a request for generating this batch request results.")
            return True
    except BaseException:
        log.exception("Failed to check batch request results generating status.")

    return False


def get_request(request, batch_request, user):
    provide_progress = request.GET.get("progress")
    provide_progress = provide_progress and provide_progress.lower() == "true"
    res = {"request": batch_request.to_api_dict()}
    if provide_progress:
        total_domains = BatchDomain.objects.filter(batch_request=batch_request).count()
        finished_domains = BatchDomain.objects.filter(
            batch_request=batch_request, status__in=(BatchDomainStatus.done, BatchDomainStatus.error)
        ).count()
        res["request"]["progress"] = f"{finished_domains}/{total_domains}"
        res["request"]["num_domains"] = total_domains

    if (
        batch_request.status == BatchRequestStatus.done
        and not batch_request.has_report_file()
        and not request_already_generating(batch_request.request_id)
    ):
        batch_async_generate_results.delay(user=user, batch_request=batch_request, site_url=get_site_url(request))

        lock_id = redis_id.batch_results_request_lock.id.format(batch_request.request_id)
        cache.add(lock_id, True)

    return api_response(res)
