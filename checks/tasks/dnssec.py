# Copyright: 2022, ECP, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
import sys
from collections import OrderedDict

import dns
import pythonwhois
from celery import shared_task
from celery.exceptions import SoftTimeLimitExceeded
from django.conf import settings
from django.core.cache import cache
from django.db import transaction

from dns.resolver import NoNameservers, LifetimeTimeout, NoAnswer, NXDOMAIN

from checks import categories, scoring
from checks.models import DnssecStatus, DomainTestDnssec, MailTestDnssec, MxStatus
from checks.resolver import dns_resolve_soa, DNSSECStatus
from checks.tasks import shared
from checks.tasks.dispatcher import check_registry, post_callback_hook
from interface import batch, batch_shared_task, redis_id
from internetnl import log

UNBOUND_PATCHED_DS_LOG = "internetnl - DS unsupported"


@shared_task(bind=True)
def web_callback(self, results, addr, req_limit_id):
    category = categories.WebDnssec()
    dtdnssec = save_results_web(addr, results, category)
    # Always calculate scores on saving.
    from checks.probes import web_probe_dnssec

    web_probe_dnssec.rated_results_by_model(dtdnssec)
    post_callback_hook(req_limit_id, self.request.id)
    return results


@batch_shared_task(bind=True)
def batch_web_callback(self, results, addr):
    category = categories.WebDnssec()
    dtdnssec = save_results_web(addr, results, category)
    # Always calculate scores on saving.
    from checks.probes import batch_web_probe_dnssec

    batch_web_probe_dnssec.rated_results_by_model(dtdnssec)
    batch.scheduler.batch_callback_hook(dtdnssec, self.request.id)


@shared_task(bind=True)
def mail_callback(self, results, addr, req_limit_id):
    category = categories.MailDnssec()
    maildomain = save_results_mail(addr, results, category)
    # Always calculate scores on saving.
    from checks.probes import mail_probe_dnssec

    mail_probe_dnssec.rated_results_by_model(maildomain)
    post_callback_hook(req_limit_id, self.request.id)
    return results


@batch_shared_task(bind=True)
def batch_mail_callback(self, results, addr):
    category = categories.MailDnssec()
    maildomain = save_results_mail(addr, results, category)
    # Always calculate scores on saving.
    from checks.probes import batch_mail_probe_dnssec

    batch_mail_probe_dnssec.rated_results_by_model(maildomain)
    batch.scheduler.batch_callback_hook(maildomain, self.request.id)


web_registered = check_registry("dnssec", web_callback)
mail_registered = check_registry("mail_dnssec", mail_callback, shared.mail_get_servers)
batch_web_registered = check_registry("batch_dnssec", batch_web_callback)
batch_mail_registered = check_registry("batch_mail_dnssec", batch_mail_callback, shared.batch_mail_get_servers)


@web_registered
@shared_task(
    bind=True,
    soft_time_limit=settings.SHARED_TASK_SOFT_TIME_LIMIT_LOW,
    time_limit=settings.SHARED_TASK_TIME_LIMIT_LOW,
)
def web_is_secure(self, url, *args, **kwargs):
    return do_web_is_secure(self, url, *args, **kwargs)


@batch_web_registered
@batch_shared_task(
    bind=True,
    soft_time_limit=settings.BATCH_SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.BATCH_SHARED_TASK_TIME_LIMIT_HIGH,
)
def batch_web_is_secure(self, url, *args, **kwargs):
    return do_web_is_secure(self, url, *args, **kwargs)


@mail_registered
@shared_task(
    bind=True,
    soft_time_limit=settings.SHARED_TASK_SOFT_TIME_LIMIT_LOW,
    time_limit=settings.SHARED_TASK_TIME_LIMIT_LOW,
)
def mail_is_secure(self, mailservers, url, *args, **kwargs):
    return do_mail_is_secure(self, mailservers, url, *args, **kwargs)


@batch_mail_registered
@batch_shared_task(
    bind=True,
    soft_time_limit=settings.BATCH_SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.BATCH_SHARED_TASK_TIME_LIMIT_HIGH,
)
def batch_mail_is_secure(self, mailservers, url, *args, **kwargs):
    return do_mail_is_secure(self, mailservers, url, *args, **kwargs)


def registrar_lookup(addr):
    """
    Get the registrar from WHOIS.

    Cache the result to avoid being ratelimited too quickly.

    """
    res = ""
    if "pythonwhois" in sys.modules and not settings.ENABLE_BATCH:
        cache_id = redis_id.whois.id.format(addr)
        cache_ttl = redis_id.whois.ttl
        cached = cache.get(cache_id)
        if cached:
            res = cached
        else:
            try:
                whois = pythonwhois.get_whois(".".join(addr.split(".")[-2:]))
                if whois and isinstance(whois, dict) and whois.get("registrar"):
                    res = ", ".join(whois["registrar"])[:250]
            except (OSError, pythonwhois.shared.WhoisException, UnicodeDecodeError, IndexError):
                pass

            cache.set(cache_id, res, cache_ttl)

    return res


@transaction.atomic
def save_results_mail(addr, results, category):
    """
    Save results in the DB for the mail test.

    """
    mailtdnssec = MailTestDnssec(domain=addr)
    mailtdnssec.save()
    testname, result = results[0]
    domain_report = {}
    subreports = {}
    # For the mail test the first result is the domain, the rest are the MX.
    for i, (domain, r) in enumerate(result.items()):
        category = category.__class__()
        dtdnssec = DomainTestDnssec(domain=domain)
        if i == 0:
            report, status, score, log = get_domain_results(domain, r, category)
            mailtdnssec.mx_status = r.get("mx_status")
            # We get the domain results here, domain does not belong to a
            # summary report like the MX.
            domain_report["dnssec_exists"] = report["dnssec_exists"]
            domain_report["dnssec_valid"] = report["dnssec_valid"]
        else:
            report, status, score, log = get_mx_results(r, category)
            subreports[domain] = report
        dtdnssec.report = report
        dtdnssec.status = status
        dtdnssec.score = score
        dtdnssec.log = log
        dtdnssec.save()
        mailtdnssec.testset.add(dtdnssec)

    # Build the summary report for the MX.
    category = category.__class__()

    # Handle the case where there are no mailservers or NULL MX variants.
    if mailtdnssec.mx_status == MxStatus.no_mx:
        category.subtests["dnssec_mx_exists"].result_no_mailservers()
    elif mailtdnssec.mx_status == MxStatus.no_null_mx:
        category.subtests["dnssec_mx_exists"].result_no_null_mx()
    elif mailtdnssec.mx_status == MxStatus.null_mx_with_other_mx:
        category.subtests["dnssec_mx_exists"].result_null_mx_with_other_mx()
    elif mailtdnssec.mx_status == MxStatus.null_mx_without_a_aaaa:
        category.subtests["dnssec_mx_exists"].result_null_mx_without_a_aaaa()
    elif mailtdnssec.mx_status == MxStatus.null_mx:
        category.subtests["dnssec_mx_exists"].result_null_mx()

    mx_report = category.gen_report()
    shared.aggregate_subreports(subreports, mx_report)

    mx_report.update(domain_report)
    mailtdnssec.report = mx_report
    mailtdnssec.save()
    return mailtdnssec


def save_results_web(addr, results, category):
    """
    Save results in the DB for the web test.

    """
    dtdnssec = DomainTestDnssec(domain=addr)
    testname, result = results[0]
    # For the web test there is going to be only one item in the result dict.
    for domain, r in result.items():
        report, status, score, log = get_domain_results(domain, r, category)
        dtdnssec.report = report
        dtdnssec.status = status
        dtdnssec.score = score
        dtdnssec.log = log
        dtdnssec.save()
    return dtdnssec


def get_domain_results(domain, r, category):
    status = r.get("status")
    score = r.get("score")
    log = ""
    registrar = registrar_lookup(domain)
    if status == DnssecStatus.secure.value:
        status = DnssecStatus.secure
        category.subtests["dnssec_exists"].result_good([[domain, registrar]])

        category.subtests["dnssec_valid"].result_good([[domain, "detail tech data secure"]])

    elif status == DnssecStatus.insecure.value:
        status = DnssecStatus.insecure
        log = r.get("log")
        unsupported_ds_algo = UNBOUND_PATCHED_DS_LOG in log
        if unsupported_ds_algo:
            category.subtests["dnssec_exists"].result_good([[domain, registrar]])

            category.subtests["dnssec_valid"].result_unsupported_ds_algo([[domain, "detail tech data insecure"]])
        else:
            log = ""  # Don't store the log for simple insecure.
            category.subtests["dnssec_exists"].result_bad([[domain, registrar]])

            category.subtests["dnssec_valid"].result_insecure([[domain, "detail tech data insecure"]])

    elif status == DnssecStatus.bogus.value:
        status = DnssecStatus.bogus
        log = r.get("log")
        category.subtests["dnssec_exists"].result_good([[domain, registrar]])

        category.subtests["dnssec_valid"].result_bad([[domain, "detail tech data bogus"]])

    elif status == DnssecStatus.servfail.value:
        status = DnssecStatus.servfail
        category.subtests["dnssec_exists"].result_servfail([[domain, registrar]])

        category.subtests["dnssec_valid"].result_servfail([[domain, "detail tech data not-tested"]])

    else:
        status = DnssecStatus.dnserror
        category.subtests["dnssec_exists"].result_resolver_error([[domain, registrar]])

        category.subtests["dnssec_valid"].result_resolver_error([[domain, "detail tech data not-tested"]])

    report = category.gen_report()

    return report, status, score, log


def get_mx_results(results, category):
    status = results.get("status")
    score = results.get("score")
    log = ""
    if status == DnssecStatus.secure.value:
        status = DnssecStatus.secure
        category.subtests["dnssec_mx_exists"].result_good()
        category.subtests["dnssec_mx_valid"].result_good()

    elif status == DnssecStatus.insecure.value:
        status = DnssecStatus.insecure
        log = results.get("log")
        unsupported_ds_algo = UNBOUND_PATCHED_DS_LOG in log
        if unsupported_ds_algo:
            category.subtests["dnssec_mx_exists"].result_good()
            category.subtests["dnssec_mx_valid"].result_unsupported_ds_algo()
        else:
            log = ""  # Don't store the log for simple insecure.
            category.subtests["dnssec_mx_exists"].result_bad()
            category.subtests["dnssec_mx_valid"].result_insecure()

    elif status == DnssecStatus.bogus.value:
        status = DnssecStatus.bogus
        log = results.get("log")
        category.subtests["dnssec_mx_exists"].result_good()
        category.subtests["dnssec_mx_valid"].result_bad()

    elif status == DnssecStatus.servfail.value:
        status = DnssecStatus.servfail
        category.subtests["dnssec_mx_exists"].result_servfail()

    else:
        status = DnssecStatus.dnserror
        category.subtests["dnssec_mx_exists"].result_resolver_error()

    report = category.gen_report()

    return report, status, score, log


def do_web_is_secure(self, url, *args, **kwargs):
    try:
        dnssec_result = dnssec_status(
            url,
            False,
            score_secure=scoring.WEB_DNSSEC_SECURE,
            score_insecure=scoring.WEB_DNSSEC_INSECURE,
            score_bogus=scoring.WEB_DNSSEC_BOGUS,
            score_error=scoring.WEB_DNSSEC_ERROR,
        )

    except SoftTimeLimitExceeded:
        log.debug("Soft time limit exceeded.")
        dnssec_result = dict(status=DnssecStatus.dnserror.value, score=scoring.WEB_DNSSEC_ERROR, log="Timed out")

    return ("is_secure", {url: dnssec_result})


def do_mail_is_secure(self, mailservers, url, *args, **kwargs):
    try:
        mx_status = shared.get_mail_servers_mxstatus(mailservers)
        if mx_status != MxStatus.has_mx:
            mailservers = [(url, mx_status)]
        else:
            mailservers.insert(0, (url, mx_status))

        res = OrderedDict()
        for domain, mx_status in mailservers:
            if domain != "":
                res[domain] = dnssec_status(
                    domain,
                    mx_status,
                    score_secure=scoring.MAIL_DNSSEC_SECURE,
                    score_insecure=scoring.MAIL_DNSSEC_INSECURE,
                    score_bogus=scoring.MAIL_DNSSEC_BOGUS,
                    score_error=scoring.MAIL_DNSSEC_ERROR,
                )

    except SoftTimeLimitExceeded:
        log.debug("Soft time limit exceeded.")
        for domain, mx_status in mailservers:
            if domain != "" and not res.get(domain):
                res[domain] = dict(
                    status=DnssecStatus.dnserror.value,
                    score=scoring.MAIL_DNSSEC_ERROR,
                    log="Timed out",
                    mx_status=mx_status,
                )

    return ("is_secure", res)


def dnssec_status(domain, mx_status, score_secure, score_insecure, score_bogus, score_error):
    """
    Check the DNSSEC status of the domain.

    """
    # Map resolver's dnssec status to test score status
    status_mapping = {
        DNSSECStatus.SECURE: (DnssecStatus.secure.value, score_secure),
        DNSSECStatus.BOGUS: (DnssecStatus.bogus.value, score_bogus),
        DNSSECStatus.INSECURE: (DnssecStatus.insecure.value, score_insecure),
    }
    try:
        log.info(f"requesting SOA for {domain=} with {mx_status=}")
        answer_dnssec_status = dns_resolve_soa(domain, raise_on_no_answer=False)
        status, score = status_mapping[answer_dnssec_status]
    except (NoNameservers, NoAnswer, NXDOMAIN, LifetimeTimeout, dns.name.EmptyLabel):
        status = DnssecStatus.dnserror.value
        score = score_error

    return dict(status=status, score=score, log=[], mx_status=mx_status)
