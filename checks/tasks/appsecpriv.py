# Copyright: 2022, ECP, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
from celery import shared_task
from celery.exceptions import SoftTimeLimitExceeded
from django.conf import settings
from django.db import transaction

from checks import categories
from checks.models import DomainTestAppsecpriv, WebTestAppsecpriv
from checks.securitytxt import securitytxt_check
from checks.tasks import SetupUnboundContext, shared
from checks.tasks.dispatcher import check_registry, post_callback_hook
from checks.tasks.http_headers import (
    HeaderCheckerContentSecurityPolicy,
    HeaderCheckerReferrerPolicy,
    HeaderCheckerXContentTypeOptions,
    HeaderCheckerXFrameOptions,
    http_headers_check,
)
from checks.tasks.shared import aggregate_subreports, results_per_domain
from interface import batch, batch_shared_task
from internetnl import log


@shared_task(bind=True)
def web_callback(self, results, domain, req_limit_id):
    """
    Save results in db.

    """
    category = categories.WebAppsecpriv()
    webdomain, results = callback(results, domain, category)
    # Always calculate scores on saving.
    from checks.probes import web_probe_appsecpriv

    web_probe_appsecpriv.rated_results_by_model(webdomain)
    post_callback_hook(req_limit_id, self.request.id)
    return results


@batch_shared_task(bind=True)
def batch_web_callback(self, results, domain):
    """
    Save results in the DB.

    """
    category = categories.WebAppsecpriv()
    webdomain, results = callback(results, domain, category)
    # Always calculate scores on saving.
    from checks.probes import batch_web_probe_appsecpriv

    batch_web_probe_appsecpriv.rated_results_by_model(webdomain)
    batch.scheduler.batch_callback_hook(webdomain, self.request.id)


@transaction.atomic
def callback(results, domain, category):
    """
    Get the results, create the necessary tables and commit in the DB.

    """
    results = results_per_domain(results)
    webdomain = WebTestAppsecpriv(domain=domain)
    webdomain.save()
    if len(results.keys()) > 0:
        for addr, res in results.items():
            dtappsecpriv = DomainTestAppsecpriv(domain=addr)
            save_results(dtappsecpriv, res, addr, domain)
            build_report(dtappsecpriv, category)
            dtappsecpriv.save()
            webdomain.webtestset.add(dtappsecpriv)
    build_summary_report(webdomain, category)
    webdomain.save()
    return webdomain, results


web_registered = check_registry("web_appsecpriv", web_callback, shared.resolve_a_aaaa)
batch_web_registered = check_registry("batch_web_appsecpriv", batch_web_callback, shared.batch_resolve_a_aaaa)


@web_registered
@shared_task(
    bind=True,
    soft_time_limit=settings.SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext,
)
def web_appsecpriv(self, af_ip_pairs, url, *args, **kwargs):
    return do_web_appsecpriv(af_ip_pairs, url, self, *args, **kwargs)


@batch_web_registered
@shared_task(
    bind=True,
    soft_time_limit=settings.BATCH_SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.BATCH_SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext,
)
def batch_web_appsecpriv(self, af_ip_pairs, url, *args, **kwargs):
    return do_web_appsecpriv(af_ip_pairs, url, self, *args, **kwargs)


def save_results(model, results, addr, domain):
    """
    Save results in the DB.

    """
    for testname, result in results:
        if testname == "http_headers":
            model.server_reachable = result.get("server_reachable", True)
            if model.server_reachable:
                model.x_frame_options_enabled = result.get("x_frame_options_enabled")
                model.x_frame_options_score = result.get("x_frame_options_score")
                model.x_frame_options_values = result.get("x_frame_options_values")
                model.x_content_type_options_enabled = result.get("x_content_type_options_enabled")
                model.x_content_type_options_score = result.get("x_content_type_options_score")
                model.x_content_type_options_values = result.get("x_content_type_options_values")
                model.referrer_policy_enabled = result.get("referrer_policy_enabled")
                model.referrer_policy_score = result.get("referrer_policy_score")
                model.referrer_policy_values = result.get("referrer_policy_values")
                model.securitytxt_enabled = result.get("securitytxt_enabled")
                model.securitytxt_score = result.get("securitytxt_score")
                model.securitytxt_errors = result.get("securitytxt_errors")
                model.securitytxt_recommendations = result.get("securitytxt_recommendations")
                model.securitytxt_found_host = result.get("securitytxt_found_host")
                model.content_security_policy_enabled = result.get("content_security_policy_enabled")
                model.content_security_policy_score = result.get("content_security_policy_score")
                model.content_security_policy_values = result.get("content_security_policy_values")

    model.save()


def build_report(model, category):
    """
    Build the report.

    """
    category = category.__class__()
    if model.server_reachable:
        if model.x_frame_options_enabled:
            category.subtests["http_x_frame"].result_good(model.x_frame_options_values)
        else:
            category.subtests["http_x_frame"].result_bad(model.x_frame_options_values)

        if model.referrer_policy_enabled:
            category.subtests["http_referrer_policy"].result_good(model.referrer_policy_values)
        else:
            category.subtests["http_referrer_policy"].result_bad(model.referrer_policy_values)

        if model.content_security_policy_enabled:
            category.subtests["http_csp"].result_good(model.content_security_policy_values)
        else:
            category.subtests["http_csp"].result_bad(model.content_security_policy_values)

        if model.x_content_type_options_enabled:
            category.subtests["http_x_content_type"].result_good(model.x_content_type_options_values)
        else:
            category.subtests["http_x_content_type"].result_bad(model.x_content_type_options_values)

        if model.securitytxt_enabled:
            default_message = [f"Retrieved security.txt from {model.securitytxt_found_host}."]
        else:
            default_message = [f"Requested security.txt from {model.securitytxt_found_host}."]

        if model.securitytxt_errors or not model.securitytxt_enabled:
            category.subtests["http_securitytxt"].result_bad(
                default_message + model.securitytxt_errors + model.securitytxt_recommendations
            )
        elif model.securitytxt_recommendations:
            category.subtests["http_securitytxt"].result_recommendations(
                default_message + model.securitytxt_recommendations
            )
        else:
            category.subtests["http_securitytxt"].result_good(default_message)

    model.report = category.gen_report()


def build_summary_report(testappsecpriv, category):
    """
    Build the summary report for all the IP addresses.

    """
    server_set = testappsecpriv.webtestset

    subreports = {}
    for server_test in server_set.all():
        subreports[server_test.domain] = server_test.report

    appsecpriv_report = category.__class__().gen_report()
    aggregate_subreports(subreports, appsecpriv_report)
    testappsecpriv.report = appsecpriv_report


def do_web_appsecpriv(af_ip_pairs, url, task, *args, **kwargs):
    try:
        results = {}
        header_checkers = [
            HeaderCheckerContentSecurityPolicy(),
            HeaderCheckerXFrameOptions(),
            HeaderCheckerReferrerPolicy(),
            HeaderCheckerXContentTypeOptions(),
        ]
        for af_ip_pair in af_ip_pairs:
            results[af_ip_pair[1]] = http_headers_check(af_ip_pair, url, header_checkers, task)
            results[af_ip_pair[1]].update(securitytxt_check(af_ip_pair, url, task))

    except SoftTimeLimitExceeded:
        log.debug("Soft time limit exceeded.")
        for af_ip_pair in af_ip_pairs:
            if not results.get(af_ip_pair[1]):
                d = {"server_reachable": False}
                for h in header_checkers:
                    d.update(h.get_negative_values())
                results[af_ip_pair[1]] = d

    return ("http_headers", results)
