# Copyright: 2022, ECP, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
import time
from timeit import default_timer as timer

from celery import shared_task
from celery.exceptions import SoftTimeLimitExceeded
from django.conf import settings
from django.core.cache import cache
from django.db import transaction

from checks import categories, scoring
from checks.models import (
    CipherOrderStatus,
    DaneStatus,
    DomainTestTls,
    ForcedHttpsStatus,
    KexHashFuncStatus,
    MailTestTls,
    MxStatus,
    OcspStatus,
    ZeroRttStatus,
    WebTestTls,
)
from checks.tasks.dispatcher import check_registry, post_callback_hook
from checks.tasks.shared import (
    aggregate_subreports,
    batch_mail_get_servers,
    batch_resolve_a_aaaa,
    get_mail_servers_mxstatus,
    mail_get_servers,
    resolve_a_aaaa,
    results_per_domain,
    TranslatableTechTableItem,
)
from checks.tasks.tls.http import http_checks
from interface import batch, batch_shared_task, redis_id

# Workaround for https://github.com/eventlet/eventlet/issues/413 for eventlet
# while monkey patching. That way we can still catch subprocess.TimeoutExpired
# instead of just Exception which may intervene with Celery's own exceptions.
# Gevent does not have the same issue.
from internetnl import log

from checks.tasks.tls.scans import ChecksMode, cert_checks, has_daneTA, check_web_tls, check_mail_tls_multiple

# Maximum number of tries on failure to establish a connection.
# Useful on one-time errors on SMTP.
MAX_TRIES = 3


test_map = {
    "web": {
        "model": WebTestTls,
        "category": categories.WebTls(),
        "testset_name": "webtestset",
        "port": 443,
    },
    "mail": {
        "model": MailTestTls,
        "category": categories.MailTls(),
        "testset_name": "testset",
        "port": 25,
    },
}


@shared_task(bind=True)
def web_callback(self, results, domain, req_limit_id):
    """
    Save results in db.

    """
    webdomain, results = callback(results, domain, "web")
    # Always calculate scores on saving.
    from checks.probes import web_probe_tls

    web_probe_tls.rated_results_by_model(webdomain)
    post_callback_hook(req_limit_id, self.request.id)
    return results


@batch_shared_task(bind=True)
def batch_web_callback(self, results, domain):
    webdomain, results = callback(results, domain, "web")
    # Always calculate scores on saving.
    from checks.probes import batch_web_probe_tls

    batch_web_probe_tls.rated_results_by_model(webdomain)
    batch.scheduler.batch_callback_hook(webdomain, self.request.id)


@shared_task(bind=True)
def mail_callback(self, results, domain, req_limit_id):
    maildomain, results = callback(results, domain, "mail")
    # Always calculate scores on saving.
    from checks.probes import mail_probe_tls

    mail_probe_tls.rated_results_by_model(maildomain)
    post_callback_hook(req_limit_id, self.request.id)
    return results


@batch_shared_task(bind=True)
def batch_mail_callback(self, results, domain):
    maildomain, results = callback(results, domain, "mail")
    # Always calculate scores on saving.
    from checks.probes import batch_mail_probe_tls

    batch_mail_probe_tls.rated_results_by_model(maildomain)
    batch.scheduler.batch_callback_hook(maildomain, self.request.id)


@transaction.atomic
def callback(results, domain, test_type):
    results = results_per_domain(results)
    if "mx_status" in results:
        return callback_null_mx(results, domain, test_type)
    testdomain = test_map[test_type]["model"](domain=domain)
    if testdomain is MailTestTls:
        testdomain.mx_status = MxStatus.has_mx
    testdomain.save()
    category = test_map[test_type]["category"]
    if len(results.keys()) > 0:
        for addr, res in results.items():
            category = category.__class__()
            dttls = DomainTestTls(domain=addr)
            dttls.port = test_map[test_type]["port"]
            save_results(dttls, res, addr, domain, test_map[test_type]["category"])
            build_report(dttls, category)
            dttls.save()
            getattr(testdomain, test_map[test_type]["testset_name"]).add(dttls)
    build_summary_report(testdomain, category)
    testdomain.save()
    return testdomain, results


def callback_null_mx(results, domain, test_type):
    testdomain = test_map[test_type]["model"](domain=domain)
    # Since we are here for the mail test and we have a variation of
    # the NULL MX record, we are pretty sure where to find the status.
    testdomain.mx_status = results["mx_status"][0][1]
    testdomain.save()
    category = test_map[test_type]["category"]
    build_summary_report(testdomain, category)
    testdomain.save()
    return testdomain, results


web_registered = check_registry("web_tls", web_callback, resolve_a_aaaa)
batch_web_registered = check_registry("batch_web_tls", batch_web_callback, batch_resolve_a_aaaa)
mail_registered = check_registry("mail_tls", mail_callback, mail_get_servers)
batch_mail_registered = check_registry("batch_mail_tls", batch_mail_callback, batch_mail_get_servers)


@web_registered
@shared_task(
    bind=True,
    soft_time_limit=settings.SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.SHARED_TASK_TIME_LIMIT_HIGH,
)
def web_cert(self, af_ip_pairs, url, *args, **kwargs):
    return do_web_cert(af_ip_pairs, url, self, *args, **kwargs)


@batch_web_registered
@batch_shared_task(
    bind=True,
    soft_time_limit=settings.BATCH_SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.BATCH_SHARED_TASK_TIME_LIMIT_HIGH,
)
def batch_web_cert(self, af_ip_pairs, url, *args, **kwargs):
    return do_web_cert(af_ip_pairs, url, self, *args, **kwargs)


@web_registered
@shared_task(
    bind=True,
    soft_time_limit=settings.SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.SHARED_TASK_TIME_LIMIT_HIGH,
)
def web_conn(self, af_ip_pairs, url, *args, **kwargs):
    return do_web_conn(af_ip_pairs, url, *args, **kwargs)


@batch_web_registered
@batch_shared_task(
    bind=True,
    soft_time_limit=settings.BATCH_SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.BATCH_SHARED_TASK_TIME_LIMIT_HIGH,
)
def batch_web_conn(self, af_ip_pairs, url, *args, **kwargs):
    return do_web_conn(af_ip_pairs, url, *args, **kwargs)


@mail_registered
@shared_task(
    bind=True,
    soft_time_limit=settings.SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.SHARED_TASK_TIME_LIMIT_HIGH,
)
def mail_smtp_starttls(self, mailservers, url, *args, **kwargs):
    return do_mail_smtp_starttls(mailservers, url, self, *args, **kwargs)


@batch_mail_registered
@batch_shared_task(
    bind=True,
    soft_time_limit=settings.BATCH_SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.BATCH_SHARED_TASK_TIME_LIMIT_HIGH,
)
def batch_mail_smtp_starttls(self, mailservers, url, *args, **kwargs):
    return do_mail_smtp_starttls(mailservers, url, self, *args, **kwargs)


@web_registered
@shared_task(
    bind=True,
    soft_time_limit=settings.SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.SHARED_TASK_TIME_LIMIT_HIGH,
)
def web_http(self, af_ip_pairs, url, *args, **kwargs):
    return do_web_http(af_ip_pairs, url, self, *args, **kwargs)


@batch_web_registered
@batch_shared_task(
    bind=True,
    soft_time_limit=settings.BATCH_SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.BATCH_SHARED_TASK_TIME_LIMIT_HIGH,
)
def batch_web_http(self, af_ip_pairs, url, *args, **kwargs):
    return do_web_http(af_ip_pairs, url, self, args, **kwargs)


def save_results(model, results, addr, domain, category):
    """
    Save results in DB.

    """
    if isinstance(category, categories.WebTls):
        for testname, result in results:
            if testname == "tls_conn":
                model.server_reachable = result.get("server_reachable", True)
                model.tls_enabled = result.get("tls_enabled")
                model.tls_enabled_score = result.get("tls_enabled_score", 0)
                if model.server_reachable and model.tls_enabled:
                    model.dh_param = result.get("dh_param")
                    model.ecdh_param = result.get("ecdh_param")
                    model.fs_bad = result.get("fs_bad")
                    model.fs_phase_out = result.get("fs_phase_out")
                    model.fs_score = result.get("fs_score")
                    model.ciphers_bad = result.get("ciphers_bad")
                    model.ciphers_phase_out = result.get("ciphers_phase_out")
                    model.ciphers_score = result.get("ciphers_score")
                    model.cipher_order = result.get("cipher_order")
                    model.cipher_order_score = result.get("cipher_order_score")
                    model.cipher_order_violation = result.get("cipher_order_violation")
                    model.protocols_good = result.get("prots_good")
                    model.protocols_sufficient = result.get("prots_sufficient")
                    model.protocols_bad = result.get("prots_bad")
                    model.protocols_phase_out = result.get("prots_phase_out")
                    model.protocols_score = result.get("prots_score")
                    model.compression = result.get("compression")
                    model.compression_score = result.get("compression_score")
                    model.secure_reneg = result.get("secure_reneg")
                    model.secure_reneg_score = result.get("secure_reneg_score")
                    model.client_reneg = result.get("client_reneg")
                    model.client_reneg_score = result.get("client_reneg_score")
                    model.zero_rtt = result.get("zero_rtt")
                    model.zero_rtt_score = result.get("zero_rtt_score")
                    model.ocsp_stapling = result.get("ocsp_stapling")
                    model.ocsp_stapling_score = result.get("ocsp_stapling_score")
                    model.kex_hash_func = result.get("kex_hash_func")
                    model.kex_hash_func_score = result.get("kex_hash_func_score")

            elif testname == "cert" and result.get("tls_cert"):
                model.cert_chain = result.get("chain")
                model.cert_trusted = result.get("trusted")
                model.cert_trusted_score = result.get("trusted_score")
                model.cert_pubkey_bad = result.get("pubkey_bad")
                model.cert_pubkey_phase_out = result.get("pubkey_phase_out")
                model.cert_pubkey_score = result.get("pubkey_score")
                model.cert_signature_bad = result.get("sigalg_bad")
                model.cert_signature_score = result.get("sigalg_score")
                model.cert_hostmatch_score = result.get("hostmatch_score")
                model.cert_hostmatch_bad = result.get("hostmatch_bad")
                model.caa_enabled = result.get("caa_result").caa_found
                model.caa_error = [ttti.to_dict() for ttti in result.get("caa_result").errors]
                model.caa_recommendations = [ttti.to_dict() for ttti in result.get("caa_result").recommendations]
                model.caa_score = result.get("caa_result").score
                model.caa_found_on_domain = result.get("caa_result").canonical_name
                model.dane_log = result.get("dane_log")
                model.dane_score = result.get("dane_score")
                model.dane_status = result.get("dane_status")
                model.dane_records = result.get("dane_records")
                model.dane_rollover = result.get("dane_rollover")

            elif testname == "http_checks":
                model.forced_https = result.get("forced_https")
                model.forced_https_score = result.get("forced_https_score")
                model.http_compression_enabled = result.get("http_compression_enabled")
                model.http_compression_score = result.get("http_compression_score")
                model.hsts_enabled = result.get("hsts_enabled")
                model.hsts_policies = result.get("hsts_policies")
                model.hsts_score = result.get("hsts_score")

    elif isinstance(category, categories.MailTls):
        for testname, result in results:
            if testname == "smtp_starttls":
                model.server_reachable = result.get("server_reachable", True)
                model.tls_enabled = result.get("tls_enabled")
                model.tls_enabled_score = result.get("tls_enabled_score", 0)
                model.could_not_test_smtp_starttls = result.get("could_not_test_smtp_starttls", False)
                if model.could_not_test_smtp_starttls:
                    # Special case where we couldn't connect for a test.
                    # Ignore all the subtests for this server.
                    continue

                if model.server_reachable and model.tls_enabled:
                    model.dh_param = result.get("dh_param")
                    model.ecdh_param = result.get("ecdh_param")
                    model.fs_bad = result.get("fs_bad")
                    model.fs_score = result.get("fs_score")
                    model.fs_phase_out = result.get("fs_phase_out")
                    model.ciphers_bad = result.get("ciphers_bad")
                    model.ciphers_phase_out = result.get("ciphers_phase_out")
                    model.ciphers_score = result.get("ciphers_score")
                    model.cipher_order = result.get("cipher_order")
                    model.cipher_order_score = result.get("cipher_order_score")
                    model.cipher_order_violation = result.get("cipher_order_violation")
                    model.protocols_good = result.get("prots_good")
                    model.protocols_sufficient = result.get("prots_sufficient")
                    model.protocols_bad = result.get("prots_bad")
                    model.protocols_phase_out = result.get("prots_phase_out")
                    model.protocols_score = result.get("prots_score")
                    model.compression = result.get("compression")
                    model.compression_score = result.get("compression_score")
                    model.secure_reneg = result.get("secure_reneg")
                    model.secure_reneg_score = result.get("secure_reneg_score")
                    model.client_reneg = result.get("client_reneg")
                    model.client_reneg_score = result.get("client_reneg_score")
                    model.zero_rtt = result.get("zero_rtt")
                    model.zero_rtt_score = result.get("zero_rtt_score")
                    # OCSP disabled for mail.
                    # model.ocsp_stapling = result.get("ocsp_stapling")
                    # model.ocsp_stapling_score = result.get("ocsp_stapling_score")
                    model.kex_hash_func = result.get("kex_hash_func")
                    model.kex_hash_func_score = result.get("kex_hash_func_score")
                if result.get("tls_cert"):
                    model.cert_chain = result.get("chain")
                    model.cert_trusted = result.get("trusted")
                    model.cert_trusted_score = result.get("trusted_score")
                    model.cert_pubkey_bad = result.get("pubkey_bad")
                    model.cert_pubkey_phase_out = result.get("pubkey_phase_out")
                    model.cert_pubkey_score = result.get("pubkey_score")
                    model.cert_signature_bad = result.get("sigalg_bad")
                    model.cert_signature_score = result.get("sigalg_score")
                    model.cert_hostmatch_score = result.get("hostmatch_score")
                    model.cert_hostmatch_bad = result.get("hostmatch_bad")
                    model.caa_enabled = result.get("caa_result").caa_found
                    model.caa_error = [ttti.to_dict() for ttti in result.get("caa_result").errors]
                    model.caa_recommendations = [ttti.to_dict() for ttti in result.get("caa_result").recommendations]
                    model.caa_score = result.get("caa_result").score
                    model.caa_found_on_domain = result.get("caa_result").canonical_name
                    model.dane_log = result.get("dane_log")
                    model.dane_score = result.get("dane_score")
                    model.dane_status = result.get("dane_status")
                    model.dane_records = result.get("dane_records")
                    model.dane_rollover = result.get("dane_rollover")

    model.save()


def build_report(dttls, category):
    def annotate_and_combine(bad_items, phaseout_items):
        return [
            bad_items + phaseout_items,
            ["detail tech data insufficient"] * len(bad_items) + ["detail tech data phase-out"] * len(phaseout_items),
        ]

    def annotate_and_combine_all(good_items, sufficient_items, bad_items, phaseout_items):
        return [
            good_items + sufficient_items + bad_items + phaseout_items,
            ["detail tech data good"] * len(good_items)
            + ["detail tech data sufficient"] * len(sufficient_items)
            + ["detail tech data insufficient"] * len(bad_items)
            + ["detail tech data phase-out"] * len(phaseout_items),
        ]

    if isinstance(category, categories.WebTls):
        if not dttls.server_reachable:
            category.subtests["https_exists"].result_unreachable()
        elif not dttls.tls_enabled:
            category.subtests["https_exists"].result_bad()
        else:
            category.subtests["https_exists"].result_good()

            if dttls.forced_https == ForcedHttpsStatus.good:
                category.subtests["https_forced"].result_good()
            elif dttls.forced_https == ForcedHttpsStatus.no_http:
                category.subtests["https_forced"].result_no_http()
            elif dttls.forced_https == ForcedHttpsStatus.no_https:
                category.subtests["https_forced"].result_no_https()
            elif dttls.forced_https == ForcedHttpsStatus.bad:
                category.subtests["https_forced"].result_bad()

            if dttls.hsts_enabled:
                if dttls.hsts_score == scoring.WEB_TLS_HSTS_GOOD:
                    category.subtests["https_hsts"].result_good(dttls.hsts_policies)
                else:
                    category.subtests["https_hsts"].result_bad_max_age(dttls.hsts_policies)
            else:
                category.subtests["https_hsts"].result_bad()

            if dttls.http_compression_enabled:
                category.subtests["http_compression"].result_bad()
            else:
                category.subtests["http_compression"].result_good()

            if not dttls.dh_param and not dttls.ecdh_param:
                category.subtests["fs_params"].result_no_dh_params()
            else:
                fs_all = annotate_and_combine(dttls.fs_bad, dttls.fs_phase_out)
                if len(dttls.fs_bad) > 0:
                    category.subtests["fs_params"].result_bad(fs_all)
                elif len(dttls.fs_phase_out) > 0:
                    category.subtests["fs_params"].result_phase_out(fs_all)
                else:
                    category.subtests["fs_params"].result_good()

            ciphers_all = annotate_and_combine(dttls.ciphers_bad, dttls.ciphers_phase_out)
            if len(dttls.ciphers_bad) > 0:
                category.subtests["tls_ciphers"].result_bad(ciphers_all)
            elif len(dttls.ciphers_phase_out) > 0:
                category.subtests["tls_ciphers"].result_phase_out(ciphers_all)
            else:
                category.subtests["tls_ciphers"].result_good()

            if dttls.cipher_order == CipherOrderStatus.bad:
                category.subtests["tls_cipher_order"].result_bad(dttls.cipher_order_violation)
            elif dttls.cipher_order == CipherOrderStatus.na:
                category.subtests["tls_cipher_order"].result_na()
            else:
                category.subtests["tls_cipher_order"].result_good()

            protocols_all = annotate_and_combine_all(
                dttls.protocols_good, dttls.protocols_sufficient, dttls.protocols_bad, dttls.protocols_phase_out
            )
            if len(dttls.protocols_bad) > 0:
                category.subtests["tls_version"].result_bad(protocols_all)
            elif len(dttls.protocols_phase_out) > 0:
                category.subtests["tls_version"].result_phase_out(protocols_all)
            else:
                category.subtests["tls_version"].result_good(protocols_all)

            if dttls.compression:
                category.subtests["tls_compression"].result_bad()
            else:
                category.subtests["tls_compression"].result_good()

            if dttls.secure_reneg:
                category.subtests["renegotiation_secure"].result_good()
            else:
                category.subtests["renegotiation_secure"].result_bad()

            if dttls.client_reneg:
                category.subtests["renegotiation_client"].result_bad()
            else:
                category.subtests["renegotiation_client"].result_good()

            if not dttls.cert_chain:
                category.subtests["cert_trust"].result_could_not_test()
            else:
                if dttls.cert_trusted == 0:
                    category.subtests["cert_trust"].result_good()
                else:
                    category.subtests["cert_trust"].result_bad(dttls.cert_chain)

                if dttls.cert_pubkey_score is None:
                    pass
                else:
                    cert_pubkey_all = annotate_and_combine(dttls.cert_pubkey_bad, dttls.cert_pubkey_phase_out)
                    if len(dttls.cert_pubkey_bad) > 0:
                        category.subtests["cert_pubkey"].result_bad(cert_pubkey_all)
                    elif len(dttls.cert_pubkey_phase_out) > 0:
                        category.subtests["cert_pubkey"].result_phase_out(cert_pubkey_all)
                    else:
                        category.subtests["cert_pubkey"].result_good()

                if dttls.cert_signature_score is None:
                    pass
                elif len(dttls.cert_signature_bad) > 0:
                    category.subtests["cert_signature"].result_bad(dttls.cert_signature_bad)
                else:
                    category.subtests["cert_signature"].result_good()

                if dttls.cert_hostmatch_score is None:
                    pass
                elif len(dttls.cert_hostmatch_bad) > 0:
                    category.subtests["cert_hostmatch"].result_bad(dttls.cert_hostmatch_bad)
                else:
                    category.subtests["cert_hostmatch"].result_good()

                if dttls.caa_enabled:
                    caa_host_message = [
                        TranslatableTechTableItem(
                            msgid="found_host", context={"host": dttls.caa_found_on_domain}
                        ).to_dict()
                    ]
                else:
                    caa_host_message = [TranslatableTechTableItem(msgid="not_found").to_dict()]
                caa_tech_table = caa_host_message + dttls.caa_errors + dttls.caa_recommendations
                if not dttls.caa_enabled or dttls.caa_errors:
                    category.subtests["web_caa"].result_bad(caa_tech_table)
                elif dttls.caa_recommendations:
                    category.subtests["web_caa"].result_recommendations(caa_tech_table)
                else:
                    category.subtests["web_caa"].result_good(caa_tech_table)

            if dttls.dane_status == DaneStatus.none:
                category.subtests["dane_exists"].result_bad()
            elif dttls.dane_status == DaneStatus.none_bogus:
                category.subtests["dane_exists"].result_bogus()
            else:
                category.subtests["dane_exists"].result_good(dttls.dane_records)

                if dttls.dane_status == DaneStatus.validated:
                    category.subtests["dane_valid"].result_good()
                elif dttls.dane_status == DaneStatus.failed:
                    category.subtests["dane_valid"].result_bad()

                # Disabled for now.
                # if dttls.dane_rollover:
                #     category.subtests['dane_rollover'].result_good()
                # else:
                #     category.subtests['dane_rollover'].result_bad()

            if dttls.zero_rtt == ZeroRttStatus.good:
                category.subtests["zero_rtt"].result_good()
            elif dttls.zero_rtt == ZeroRttStatus.bad:
                category.subtests["zero_rtt"].result_bad()
            elif dttls.zero_rtt == ZeroRttStatus.na:
                category.subtests["zero_rtt"].result_na()

            if dttls.ocsp_stapling == OcspStatus.good:
                category.subtests["ocsp_stapling"].result_good()
            elif dttls.ocsp_stapling == OcspStatus.not_trusted:
                category.subtests["ocsp_stapling"].result_not_trusted()
            elif dttls.ocsp_stapling == OcspStatus.ok:
                category.subtests["ocsp_stapling"].result_ok()

            if dttls.kex_hash_func == KexHashFuncStatus.good:
                category.subtests["kex_hash_func"].result_good()
            elif dttls.kex_hash_func == KexHashFuncStatus.bad:
                category.subtests["kex_hash_func"].result_bad()
            elif dttls.kex_hash_func == KexHashFuncStatus.unknown:
                category.subtests["kex_hash_func"].result_unknown()

    elif isinstance(category, categories.MailTls):
        if dttls.could_not_test_smtp_starttls:
            category.subtests["starttls_exists"].result_could_not_test()
        elif not dttls.server_reachable:
            category.subtests["starttls_exists"].result_unreachable()
        elif not dttls.tls_enabled:
            category.subtests["starttls_exists"].result_bad()
        else:
            category.subtests["starttls_exists"].result_good()

            if not dttls.dh_param and not dttls.ecdh_param:
                category.subtests["fs_params"].result_no_dh_params()
            else:
                fs_all = annotate_and_combine(dttls.fs_bad, dttls.fs_phase_out)
                if len(dttls.fs_bad) > 0:
                    category.subtests["fs_params"].result_bad(fs_all)
                elif len(dttls.fs_phase_out) > 0:
                    category.subtests["fs_params"].result_phase_out(fs_all)
                else:
                    category.subtests["fs_params"].result_good()

            ciphers_all = annotate_and_combine(dttls.ciphers_bad, dttls.ciphers_phase_out)
            if len(dttls.ciphers_bad) > 0:
                category.subtests["tls_ciphers"].result_bad(ciphers_all)
            elif len(dttls.ciphers_phase_out) > 0:
                category.subtests["tls_ciphers"].result_phase_out(ciphers_all)
            else:
                category.subtests["tls_ciphers"].result_good()
            if dttls.cipher_order == CipherOrderStatus.bad:
                category.subtests["tls_cipher_order"].result_bad(dttls.cipher_order_violation)
            elif dttls.cipher_order == CipherOrderStatus.na:
                category.subtests["tls_cipher_order"].result_na()
            else:
                category.subtests["tls_cipher_order"].result_good()

            protocols_all = annotate_and_combine_all(
                dttls.protocols_good, dttls.protocols_sufficient, dttls.protocols_bad, dttls.protocols_phase_out
            )
            if len(dttls.protocols_bad) > 0:
                category.subtests["tls_version"].result_bad(protocols_all)
            elif len(dttls.protocols_phase_out) > 0:
                category.subtests["tls_version"].result_phase_out(protocols_all)
            else:
                category.subtests["tls_version"].result_good(protocols_all)

            if dttls.compression:
                category.subtests["tls_compression"].result_bad()
            else:
                category.subtests["tls_compression"].result_good()

            if dttls.secure_reneg:
                category.subtests["renegotiation_secure"].result_good()
            else:
                category.subtests["renegotiation_secure"].result_bad()

            if dttls.client_reneg:
                category.subtests["renegotiation_client"].result_bad()
            else:
                category.subtests["renegotiation_client"].result_good()

            if not dttls.cert_chain:
                category.subtests["cert_trust"].result_could_not_test()
            else:
                if dttls.cert_trusted == 0:
                    category.subtests["cert_trust"].result_good()
                else:
                    category.subtests["cert_trust"].result_bad(dttls.cert_chain)

                if dttls.cert_pubkey_score is None:
                    pass
                else:
                    cert_pubkey_all = annotate_and_combine(dttls.cert_pubkey_bad, dttls.cert_pubkey_phase_out)
                    if len(dttls.cert_pubkey_bad) > 0:
                        category.subtests["cert_pubkey"].result_bad(cert_pubkey_all)
                    elif len(dttls.cert_pubkey_phase_out) > 0:
                        category.subtests["cert_pubkey"].result_phase_out(cert_pubkey_all)
                    else:
                        category.subtests["cert_pubkey"].result_good()

                if dttls.cert_signature_score is None:
                    pass
                elif len(dttls.cert_signature_bad) > 0:
                    category.subtests["cert_signature"].result_bad(dttls.cert_signature_bad)
                else:
                    category.subtests["cert_signature"].result_good()

                if dttls.cert_hostmatch_score is None:
                    pass
                elif len(dttls.cert_hostmatch_bad) > 0:
                    # HACK: for DANE-TA(2) and hostname mismatch!
                    # Give a fail only if DANE-TA *is* present, otherwise info.
                    if has_daneTA(dttls.dane_records):
                        category.subtests["cert_hostmatch"].result_has_daneTA(dttls.cert_hostmatch_bad)
                    else:
                        category.subtests["cert_hostmatch"].result_bad(dttls.cert_hostmatch_bad)
                else:
                    category.subtests["cert_hostmatch"].result_good()

            if dttls.caa_enabled:
                caa_host_message = [
                    TranslatableTechTableItem(msgid="found_host", context={"host": dttls.caa_found_on_domain}).to_dict()
                ]
            else:
                caa_host_message = [TranslatableTechTableItem(msgid="not_found").to_dict()]
            caa_tech_table = caa_host_message + dttls.caa_errors + dttls.caa_recommendations
            if not dttls.caa_enabled or dttls.caa_errors:
                category.subtests["mail_caa"].result_bad(caa_tech_table)
            elif dttls.caa_recommendations:
                category.subtests["mail_caa"].result_recommendations(caa_tech_table)
            else:
                category.subtests["mail_caa"].result_good(caa_tech_table)

            if dttls.dane_status == DaneStatus.none:
                category.subtests["dane_exists"].result_bad()
            elif dttls.dane_status == DaneStatus.none_bogus:
                category.subtests["dane_exists"].result_bogus()
            else:
                category.subtests["dane_exists"].result_good(dttls.dane_records)

                if dttls.dane_status == DaneStatus.validated:
                    category.subtests["dane_valid"].result_good()
                elif dttls.dane_status == DaneStatus.failed:
                    category.subtests["dane_valid"].result_bad()

                if dttls.dane_rollover:
                    category.subtests["dane_rollover"].result_good()
                else:
                    category.subtests["dane_rollover"].result_bad()

            if dttls.zero_rtt == ZeroRttStatus.good:
                category.subtests["zero_rtt"].result_good()
            elif dttls.zero_rtt == ZeroRttStatus.bad:
                category.subtests["zero_rtt"].result_bad()
            elif dttls.zero_rtt == ZeroRttStatus.na:
                category.subtests["zero_rtt"].result_na()

            # OCSP disabled for mail.
            # if dttls.ocsp_stapling == OcspStatus.good:
            #     category.subtests['ocsp_stapling'].result_good()
            # elif dttls.ocsp_stapling == OcspStatus.not_trusted:
            #     category.subtests['ocsp_stapling'].result_not_trusted()
            # elif dttls.ocsp_stapling == OcspStatus.ok:
            #     category.subtests['ocsp_stapling'].result_ok()

            if dttls.kex_hash_func == KexHashFuncStatus.good:
                category.subtests["kex_hash_func"].result_good()
            elif dttls.kex_hash_func == KexHashFuncStatus.bad:
                category.subtests["kex_hash_func"].result_bad()
            elif dttls.kex_hash_func == KexHashFuncStatus.unknown:
                category.subtests["kex_hash_func"].result_unknown()

    dttls.report = category.gen_report()


def build_summary_report(testtls, category):
    """
    Build the summary report for all the IP addresses.

    """
    category = category.__class__()
    if isinstance(category, categories.WebTls):
        category.subtests["https_exists"].result_bad()
        server_set = testtls.webtestset

    elif isinstance(category, categories.MailTls):
        if testtls.mx_status == MxStatus.null_mx:
            category.subtests["starttls_exists"].result_null_mx()
        elif testtls.mx_status == MxStatus.no_null_mx:
            category.subtests["starttls_exists"].result_no_null_mx()
        elif testtls.mx_status == MxStatus.null_mx_with_other_mx:
            category.subtests["starttls_exists"].result_null_mx_with_other_mx()
        elif testtls.mx_status == MxStatus.null_mx_without_a_aaaa:
            category.subtests["starttls_exists"].result_null_mx_without_a_aaaa()
        else:
            category.subtests["starttls_exists"].result_no_mailservers()
        server_set = testtls.testset

    report = category.gen_report()
    subreports = {}
    for server_test in server_set.all():
        subreports[server_test.domain] = server_test.report

    aggregate_subreports(subreports, report)
    testtls.report = report


def do_web_cert(af_ip_pairs, url, *args, **kwargs):
    """
    Check the web server's certificate.

    """
    try:
        results = {}
        for af_ip_pair in af_ip_pairs:
            results[af_ip_pair[1]] = cert_checks(url, ChecksMode.WEB, af_ip_pair, *args, **kwargs)
    except SoftTimeLimitExceeded:
        log.debug("Soft time limit exceeded. Url: %s", url)
        for af_ip_pair in af_ip_pairs:
            if not results.get(af_ip_pair[1]):
                results[af_ip_pair[1]] = dict(tls_cert=False)

    return ("cert", results)


def do_web_conn(af_ip_pairs, url, *args, **kwargs):
    """
    Start all the TLS related checks for the web test.

    """
    try:
        results = {}
        for af_ip_pair in af_ip_pairs:
            results[af_ip_pair[1]] = check_web_tls(url, af_ip_pair, args, kwargs)
    except SoftTimeLimitExceeded:
        log.debug("Soft time limit exceeded. Url: %s", url)
        for af_ip_pair in af_ip_pairs:
            if not results.get(af_ip_pair[1]):
                results[af_ip_pair[1]] = dict(server_reachable=False, tls_enabled=False)

    return ("tls_conn", results)


def do_mail_smtp_starttls(mailservers, url, *args, **kwargs):
    """
    Start all the TLS related checks for the mail test.

    If we already have cached results for these mailservers from another mail
    test use those to avoid contacting well known mailservers all the time.

    """
    # Check for NULL MX and return immediately.
    mx_status = get_mail_servers_mxstatus(mailservers)
    if mx_status != MxStatus.has_mx:
        return ("smtp_starttls", {"mx_status": mx_status})

    results = {server: False for server, _, _ in mailservers}
    try:
        start = timer()
        # Sleep in order for the ipv6 mail test to finish.
        # Cheap counteraction for some mailservers that allow only one
        # concurrent connection per IP.
        time.sleep(5)

        # Always try to get cached results (within the allowed time frame) to
        # avoid continuously testing popular mail hosting providers.
        cache_ttl = redis_id.mail_starttls.ttl

        for server, dane_cb_data, _ in mailservers:
            # Pull in any cached results
            cache_id = redis_id.mail_starttls.id.format(server)
            results[server] = cache.get(cache_id, False)
            log.debug(f"=========== pulled {cache_id=} for {server=} data {results[server]}")
        while timer() - start < cache_ttl and (not results or not all(results.values())):
            servers_to_check = [
                (server, dane_cb_data) for server, dane_cb_data, _ in mailservers if not results[server]
            ]
            log.debug(f"=========== checking remaining {servers_to_check=}")
            results.update(check_mail_tls_multiple(servers_to_check))
            time.sleep(1)
        for server, server_result in results.items():
            cache_id = redis_id.mail_starttls.id.format(server)
            cache.set(cache_id, server_result, cache_ttl)
            log.debug(f"=========== writing to {cache_id=} for {server=}")
            if results[server] is False:
                results[server] = dict(tls_enabled=False, could_not_test_smtp_starttls=True)
    except SoftTimeLimitExceeded:
        log.debug("Soft time limit exceeded.")
        for server in results:
            if results[server] is False:
                results[server] = dict(tls_enabled=False, could_not_test_smtp_starttls=True)
    return "smtp_starttls", results


def do_web_http(af_ip_pairs, url, *args, **kwargs):
    """
    Start all the HTTP related checks for the web test.

    """
    try:
        results = {}
        for af_ip_pair in af_ip_pairs:
            results[af_ip_pair[1]] = http_checks(af_ip_pair, url)

    except SoftTimeLimitExceeded:
        log.debug("Soft time limit exceeded.")
        for af_ip_pair in af_ip_pairs:
            if not results.get(af_ip_pair[1]):
                results[af_ip_pair[1]] = dict(
                    forced_https=False,
                    forced_https_score=scoring.WEB_TLS_FORCED_HTTPS_BAD,
                    http_compression_enabled=True,
                    http_compression_score=scoring.WEB_TLS_HTTP_COMPRESSION_BAD,
                    hsts_enabled=False,
                    hsts_policies=[],
                    hsts_score=scoring.WEB_TLS_HSTS_BAD,
                )

    return ("http_checks", results)
