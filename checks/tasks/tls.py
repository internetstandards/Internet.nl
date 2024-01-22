# Copyright: 2022, ECP, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
import logging
import time
from binascii import hexlify
from enum import Enum
from timeit import default_timer as timer
from typing import List
from urllib.parse import urlparse

import eventlet
import requests
from celery import shared_task
from celery.exceptions import SoftTimeLimitExceeded
from cryptography.hazmat.backends.openssl import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.x509 import (
    NameOID,
    Certificate,
)
from django.conf import settings
from django.db import transaction
from nassl.ephemeral_key_info import DhEphemeralKeyInfo, EcDhEphemeralKeyInfo, OpenSslEvpPkeyEnum
from sslyze import (
    Scanner,
    ServerScanRequest,
    ServerNetworkLocation,
    ServerScanStatusEnum,
    ScanCommand,
    TlsVersionEnum,
    CipherSuiteAcceptedByServer,
    ServerNetworkConfiguration,
    ProtocolWithOpportunisticTlsEnum,
)

from sslyze.plugins.certificate_info._certificate_utils import (
    parse_subject_alternative_name_extension,
    get_common_names,
)

from checks import categories, scoring
from checks.http_client import http_get_ip
from checks.models import (
    CipherOrderStatus,
    DaneStatus,
    DomainTestTls,
    ForcedHttpsStatus,
    KexHashFuncStatus,
    MailTestTls,
    MxStatus,
    OcspStatus,
    WebTestTls,
    ZeroRttStatus,
)
from checks.tasks import SetupUnboundContext
from checks.tasks.dispatcher import check_registry, post_callback_hook
from checks.tasks.http_headers import (
    HeaderCheckerContentEncoding,
    HeaderCheckerStrictTransportSecurity,
    http_headers_check,
)
from checks.tasks.tls_constants import (
    FFDHE_GENERATOR,
    FFDHE2048_PRIME,
    FFDHE_SUFFICIENT_PRIMES,
    SIGALG_GOOD,
    EC_PHASE_OUT,
    EC_GOOD,
    CIPHERS_PHASE_OUT,
    CIPHERS_GOOD,
    CIPHERS_SUFFICIENT,
    DH_MIN_KEY_SIZE,
    ECDH_MIN_KEY_SIZE,
    CERT_RSA_DSA_MIN_KEY_SIZE,
    CERT_CURVE_MIN_KEY_SIZE,
    CERT_EC_CURVES_GOOD,
    CERT_CURVES_GOOD,
    CERT_EC_CURVES_PHASE_OUT,
)
from checks.tasks.shared import (
    aggregate_subreports,
    batch_mail_get_servers,
    batch_resolve_a_aaaa,
    get_mail_servers_mxstatus,
    mail_get_servers,
    resolve_a_aaaa,
    resolve_dane,
    results_per_domain,
)
from interface import batch, batch_shared_task, redis_id

# Workaround for https://github.com/eventlet/eventlet/issues/413 for eventlet
# while monkey patching. That way we can still catch subprocess.TimeoutExpired
# instead of just Exception which may intervene with Celery's own exceptions.
# Gevent does not have the same issue.
from internetnl import log

if eventlet.patcher.is_monkey_patched("subprocess"):
    subprocess = eventlet.import_patched("subprocess")
else:
    import subprocess


# Maximum number of tries on failure to establish a connection.
# Useful on one-time errors on SMTP.
MAX_TRIES = 3


SSLYZE_SCAN_COMMANDS = {
    ScanCommand.SSL_2_0_CIPHER_SUITES,
    ScanCommand.SSL_3_0_CIPHER_SUITES,
    ScanCommand.TLS_1_0_CIPHER_SUITES,
    ScanCommand.TLS_1_1_CIPHER_SUITES,
    ScanCommand.TLS_1_2_CIPHER_SUITES,
    ScanCommand.TLS_1_3_CIPHER_SUITES,
    ScanCommand.TLS_COMPRESSION,
    ScanCommand.TLS_1_3_EARLY_DATA,
    ScanCommand.SESSION_RENEGOTIATION,
    ScanCommand.ELLIPTIC_CURVES,
}


root_fingerprints = None
with open(settings.CA_FINGERPRINTS) as f:
    root_fingerprints = f.read().splitlines()

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


class ChecksMode(Enum):
    WEB = (0,)
    MAIL = 1


class TLSException(Exception):
    pass


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
    base=SetupUnboundContext,
)
def web_cert(self, af_ip_pairs, url, *args, **kwargs):
    return do_web_cert(af_ip_pairs, url, self, *args, **kwargs)


@batch_web_registered
@batch_shared_task(
    bind=True,
    soft_time_limit=settings.BATCH_SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.BATCH_SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext,
)
def batch_web_cert(self, af_ip_pairs, url, *args, **kwargs):
    return do_web_cert(af_ip_pairs, url, self, *args, **kwargs)


@web_registered
@shared_task(
    bind=True,
    soft_time_limit=settings.SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext,
)
def web_conn(self, af_ip_pairs, url, *args, **kwargs):
    return do_web_conn(af_ip_pairs, url, *args, **kwargs)


@batch_web_registered
@batch_shared_task(
    bind=True,
    soft_time_limit=settings.BATCH_SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.BATCH_SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext,
)
def batch_web_conn(self, af_ip_pairs, url, *args, **kwargs):
    return do_web_conn(af_ip_pairs, url, *args, **kwargs)


@mail_registered
@shared_task(
    bind=True,
    soft_time_limit=settings.SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext,
)
def mail_smtp_starttls(self, mailservers, url, *args, **kwargs):
    return do_mail_smtp_starttls(mailservers, url, self, *args, **kwargs)


@batch_mail_registered
@batch_shared_task(
    bind=True,
    soft_time_limit=settings.BATCH_SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.BATCH_SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext,
)
def batch_mail_smtp_starttls(self, mailservers, url, *args, **kwargs):
    return do_mail_smtp_starttls(mailservers, url, self, *args, **kwargs)


@web_registered
@shared_task(
    bind=True,
    soft_time_limit=settings.SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext,
)
def web_http(self, af_ip_pairs, url, *args, **kwargs):
    return do_web_http(af_ip_pairs, url, self, *args, **kwargs)


@batch_web_registered
@batch_shared_task(
    bind=True,
    soft_time_limit=settings.BATCH_SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.BATCH_SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext,
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
                category.subtests["tls_cipher_order"].result_bad()
            elif dttls.cipher_order == CipherOrderStatus.na:
                category.subtests["tls_cipher_order"].result_na()
            elif dttls.cipher_order == CipherOrderStatus.not_seclevel:
                (cipher1, cipher2, violated_rule) = dttls.cipher_order_violation
                category.subtests["tls_cipher_order"].result_seclevel_bad([[cipher1, cipher2]])
            elif dttls.cipher_order == CipherOrderStatus.not_prescribed:
                # Provide tech_data that supplies values for two rows each of
                # two cells to fill in a table like so:
                # Web server IP address | Ciphers | Rule #
                # -------------------------------------------------------------
                # 1.2.3.4               | cipher1 | ' '
                # ...                   | cipher2 | violated_rule
                (cipher1, cipher2, violated_rule) = dttls.cipher_order_violation
                # The 5th rule is only informational.
                if violated_rule == 5:
                    category.subtests["tls_cipher_order"].result_score_info([[cipher1, cipher2], [" ", violated_rule]])
                else:
                    category.subtests["tls_cipher_order"].result_score_warning(
                        [[cipher1, cipher2], [" ", violated_rule]]
                    )
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
                category.subtests["tls_cipher_order"].result_bad()
            elif dttls.cipher_order == CipherOrderStatus.na:
                category.subtests["tls_cipher_order"].result_na()
            elif dttls.cipher_order == CipherOrderStatus.not_seclevel:
                (cipher1, cipher2, violated_rule) = dttls.cipher_order_violation
                category.subtests["tls_cipher_order"].result_seclevel_bad([[cipher1, cipher2]])
            elif dttls.cipher_order == CipherOrderStatus.not_prescribed:
                # Provide tech_data that supplies values for two rows each of
                # two cells to fill in a table like so:
                # Web server IP address | Ciphers | Rule #
                # -------------------------------------------------------------
                # 1.2.3.4               | cipher1 | ' '
                # ...                   | cipher2 | violated_rule
                (cipher1, cipher2, violated_rule) = dttls.cipher_order_violation
                # The 5th rule is only informational.
                if violated_rule == 5:
                    category.subtests["tls_cipher_order"].result_score_info([[cipher1, cipher2], [" ", violated_rule]])
                else:
                    category.subtests["tls_cipher_order"].result_score_warning(
                        [[cipher1, cipher2], [" ", violated_rule]]
                    )
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


def dane(
    url: str,
    port: int,
    chain: List[Certificate],
    task,
    dane_cb_data,
    score_none,
    score_none_bogus,
    score_failed,
    score_validated,
):
    """
    Check if there are TLSA records, if they are valid and if a DANE rollover
    scheme is currently in place.

    """
    score = score_none
    status = DaneStatus.none
    records = []
    stdout = ""
    rollover = False

    continue_testing = False

    cb_data = dane_cb_data or resolve_dane(task, port, url)

    # Check if there is a TLSA record, if TLSA records are bogus or NXDOMAIN is
    # returned for the TLSA domain (faulty signer).
    if cb_data.get("bogus"):
        status = DaneStatus.none_bogus
        score = score_none_bogus
    elif cb_data.get("data") and cb_data.get("secure"):
        # If there is a secure TLSA record check for the existence of
        # possible bogus (unsigned) NXDOMAIN in A.
        tmp_data = resolve_dane(task, port, url, check_nxdomain=True)
        if tmp_data.get("nxdomain") and tmp_data.get("bogus"):
            status = DaneStatus.none_bogus
            score = score_none_bogus
        else:
            continue_testing = True

    if not continue_testing:
        return dict(
            dane_score=score,
            dane_status=status,
            dane_log=stdout,
            dane_records=records,
            dane_rollover=rollover,
        )

    # Record TLSA data and also check for DANE rollover types.
    # Accepted pairs are:
    # * 3 x x - 3 x x
    # * 3 x x - 2 x x
    two_x_x = 0
    three_x_x = 0
    for cert_usage, selector, match, data in cb_data["data"]:
        if port == 25 and cert_usage in (0, 1):
            # Ignore PKIX TLSA records for mail.
            continue

        records.append(f"{cert_usage} {selector} {match} {data}")
        if cert_usage == 2:
            two_x_x += 1
        elif cert_usage == 3:
            three_x_x += 1

    if not records:
        return dict(
            dane_score=score,
            dane_status=status,
            dane_log=stdout,
            dane_records=records,
            dane_rollover=rollover,
        )

    if three_x_x > 1 or (three_x_x and two_x_x):
        rollover = True

    # Remove the trailing dot if any.
    hostname = url.rstrip(".")

    chain_pem = []
    for cert in chain:
        chain_pem.append(cert.public_bytes(Encoding.PEM).decode("ascii"))
    chain_txt = "\n".join(chain_pem)
    with subprocess.Popen(
        [
            settings.LDNS_DANE,
            "-c",
            "/dev/stdin",  # Read certificate chain from stdin
            "-n",  # Do not validate hostname
            "-T",  # Exit status 2 for PKIX without (secure) TLSA records
            "-r",
            settings.IPV4_IP_RESOLVER_INTERNAL_VALIDATING,  # Use internal unbound resolver
            "-f",
            settings.CA_CERTIFICATES,  # CA file
            "verify",
            hostname,
            str(port),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
        universal_newlines=True,
    ) as proc:
        try:
            res = proc.communicate(input=chain_txt, timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            res = proc.communicate()

    # status 0: DANE validate
    # status 1: ERROR
    # status 2: PKIX ok, no TLSA
    if res:
        stdout, stderr = res

        if "No usable TLSA records" in stdout or "No usable TLSA records" in stderr:
            score = score_failed
            status = DaneStatus.failed
        elif "No TLSA records" not in stdout and "No TLSA records" not in stderr:
            if proc.returncode == 0:
                score = score_validated
                status = DaneStatus.validated
            elif proc.returncode == 1:
                score = score_failed
                status = DaneStatus.failed

        # Log stderr if stdout is empty.
        if not stdout:
            stdout = stderr

    return dict(
        dane_score=score,
        dane_status=status,
        dane_log=stdout,
        dane_records=records,
        dane_rollover=rollover,
    )


def is_root_cert(cert):
    """
    Check if the certificate is a root certificate.

    """
    digest = cert.fingerprint(hashes.SHA1())
    digest = hexlify(digest).decode("ascii")
    return digest.upper() in root_fingerprints


def get_common_name(cert):
    """
    Get the commonName of the certificate.

    """
    value = "-"
    try:
        common_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0]
        if common_name:
            value = common_name.value
    except (IndexError, ValueError):
        pass
    return value


def do_web_cert(af_ip_pairs, url, task, *args, **kwargs):
    """
    Check the web server's certificate.

    """
    try:
        results = {}
        for af_ip_pair in af_ip_pairs:
            results[af_ip_pair[1]] = cert_checks(url, ChecksMode.WEB, task, af_ip_pair, *args, **kwargs)
    except SoftTimeLimitExceeded:
        log.debug("Soft time limit exceeded. Url: %s", url)
        for af_ip_pair in af_ip_pairs:
            if not results.get(af_ip_pair[1]):
                results[af_ip_pair[1]] = dict(tls_cert=False)

    return ("cert", results)


def cert_checks(hostname, mode, task, af_ip_pair=None, dane_cb_data=None, *args, **kwargs):
    """
    Perform certificate checks.

    """
    # TODO: this does use our trust store
    log.info(f"starting cert sslyze scan for {hostname} {af_ip_pair} {mode}")
    if mode == ChecksMode.WEB:
        port = 443
        scan = ServerScanRequest(
            server_location=ServerNetworkLocation(hostname=hostname, ip_address=af_ip_pair[1], port=port),
            scan_commands={ScanCommand.CERTIFICATE_INFO},
        )
    elif mode == ChecksMode.MAIL:
        port = 25
        scan = ServerScanRequest(
            server_location=ServerNetworkLocation(hostname=hostname, port=port),
            network_configuration=ServerNetworkConfiguration(
                tls_server_name_indication=hostname, tls_opportunistic_encryption=ProtocolWithOpportunisticTlsEnum.SMTP
            ),
            scan_commands={ScanCommand.CERTIFICATE_INFO},
        )
    else:
        raise ValueError
    scanner = Scanner(per_server_concurrent_connections_limit=1)
    scanner.queue_scans([scan])
    result = next(scanner.get_results())
    print(f"scan status result {result.scan_status}")
    if result.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
        log.info(f"sslyze scan for mail on {hostname} failed: no connectivity")
        return dict(tls_cert=False)

        # elif mode == ChecksMode.MAIL:
        #     debug_cert_chain = DebugCertChainMail
        #     conn_wrapper = SMTPConnection
        #     conn_wrapper_args["server_name"] = url
        #     conn_wrapper_args["send_SNI"] = starttls_details.dane_cb_data.get(
        #         "data"
        #     ) and starttls_details.dane_cb_data.get("secure")

        #
        # if (
        #     not starttls_details
        #     or starttls_details.debug_chain is None
        #     or starttls_details.trusted_score is None
        #     or starttls_details.conn_port is None
        # ):
        #     # All the checks inside the smtp_starttls test are done in series.
        #     # If we have all the certificate related information we need from a
        #     # previous check, skip this connection.
        #     # check chain validity (sort of NCSC guideline B3-4)
        #
        #     with conn_wrapper(**conn_wrapper_args).conn as conn:
        #         with ConnectionChecker(conn, mode) as checker:
        #             verify_score, verify_result = checker.check_cert_trust()
        #             debug_chain = debug_cert_chain(conn.get_peer_certificate_chain())
        #             conn_port = conn.port
        # else:
        #     verify_score, verify_result = starttls_details.trusted_score
        #     debug_chain = starttls_details.debug_chain
        #     conn_port = starttls_details.conn_port

    # TODO: check trust

    if not result.scan_result.certificate_info.result.certificate_deployments:
        return dict(tls_cert=False)

    cert_deployment = result.scan_result.certificate_info.result.certificate_deployments[0]
    leaf_cert = cert_deployment.received_certificate_chain[0]

    # TODO: use the right scoring set
    hostmatch_bad = []
    hostmatch_score = scoring.WEB_TLS_HOSTMATCH_GOOD
    if not cert_deployment.leaf_certificate_subject_matches_hostname:
        hostmatch_score = scoring.WEB_TLS_HOSTMATCH_BAD

        # Extract all names from a certificate, taken from sslyze' _cert_chain_analyzer.py
        subj_alt_name_ext = parse_subject_alternative_name_extension(leaf_cert)
        subj_alt_name_as_list = [("DNS", name) for name in subj_alt_name_ext.dns_names]
        subj_alt_name_as_list.extend([("IP Address", ip) for ip in subj_alt_name_ext.ip_addresses])
        certificate_names = {
            "subject": (tuple([("commonName", name) for name in get_common_names(leaf_cert.subject)]),),
            "subjectAltName": tuple(subj_alt_name_as_list),
        }
        hostmatch_bad = certificate_names

    pubkey_score, pubkey_bad, pubkey_phase_out = check_pubkey(cert_deployment.received_certificate_chain)

    # NCSC guideline B3-2
    sigalg_bad = {}
    sigalg_score = scoring.WEB_TLS_SIGNATURE_GOOD
    for cert in cert_deployment.received_certificate_chain:
        # Only validate signarture of non-root certificates
        if not is_root_cert(cert):
            sigalg = cert.signature_algorithm_oid
            # Check oids
            if sigalg not in SIGALG_GOOD:
                sigalg_bad[get_common_name(cert)] = sigalg._name
                sigalg_score = scoring.WEB_TLS_SIGNATURE_BAD

    chain_str = []
    for cert in cert_deployment.received_certificate_chain:
        chain_str.append(get_common_name(cert))

    dane_results = dane(
        hostname,
        port,
        cert_deployment.received_certificate_chain,
        task,
        dane_cb_data,
        scoring.WEB_TLS_DANE_NONE,
        scoring.WEB_TLS_DANE_NONE_BOGUS,
        scoring.WEB_TLS_DANE_FAILED,
        scoring.WEB_TLS_DANE_VALIDATED,
    )

    results = dict(
        tls_cert=True,
        chain=chain_str,
        trusted=scoring.WEB_TLS_TRUSTED_GOOD,
        trusted_score=scoring.MAIL_TLS_TRUSTED_GOOD,
        pubkey_bad=pubkey_bad,
        pubkey_phase_out=pubkey_phase_out,
        pubkey_score=pubkey_score,
        sigalg_bad=sigalg_bad,
        sigalg_score=sigalg_score,
        hostmatch_bad=hostmatch_bad,
        hostmatch_score=hostmatch_score,
    )
    results.update(dane_results)

    return results


def check_pubkey(certificates: List[Certificate]):
    # NCSC guidelines B3-3, B5-1
    bad_pubkey = []
    phase_out_pubkey = []
    # TODO: use mail score where appropriate
    pubkey_score = scoring.WEB_TLS_PUBKEY_GOOD
    for cert in certificates:
        common_name = get_common_name(cert)
        public_key = cert.public_key()
        public_key_type = type(public_key)
        key_size = public_key.key_size

        failed_key_type = ""
        curve = ""
        if public_key_type is rsa.RSAPublicKey and key_size < CERT_RSA_DSA_MIN_KEY_SIZE:
            failed_key_type = public_key_type.__name__
        elif public_key_type is dsa.DSAPublicKey and key_size < CERT_RSA_DSA_MIN_KEY_SIZE:
            failed_key_type = public_key_type.__name__
        # TODO: DH type?
        # elif public_key_type is DHPublicKey and key_size < 2048:
        #    failed_key_type = "DHPublicKey"
        elif public_key_type in CERT_CURVES_GOOD and key_size < CERT_CURVE_MIN_KEY_SIZE:
            failed_key_type = public_key_type.__name__
        elif public_key_type is EllipticCurvePublicKey and (
            key_size < CERT_CURVE_MIN_KEY_SIZE or public_key.curve not in CERT_EC_CURVES_GOOD
        ):
            failed_key_type = public_key_type.__name__
        if failed_key_type:
            message = f"{common_name}: {failed_key_type}-{key_size} key_size"
            if curve:
                message += f", curve: {curve}"
            if public_key.curve in CERT_EC_CURVES_PHASE_OUT:
                phase_out_pubkey.append(message)
            else:
                bad_pubkey.append(message)
                pubkey_score = scoring.WEB_TLS_PUBKEY_BAD
    return pubkey_score, bad_pubkey, phase_out_pubkey


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


def do_mail_smtp_starttls(mailservers, url, task, *args, **kwargs):
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
        # TODO: re-enable this cache
        # TODO: limited to 1 mailserver right now
        for server, dane_cb_data, _ in mailservers[:1]:
            results[server] = check_mail_tls(server, dane_cb_data, task)
        # while timer() - start < cache_ttl and not all(results.values()) > 0:
        #     for server, dane_cb_data, _ in mailservers:
        #         if results[server]:
        #             continue
        #         # Check if we already have cached results.
        #         cache_id = redis_id.mail_starttls.id.format(server)
        #         if cache.add(cache_id, False, cache_ttl):
        #             # We do not have cached results, get them and cache them.
        #             results[server] = check_mail_tls(server, dane_cb_data, task)
        #             cache.set(cache_id, results[server], cache_ttl)
        #         else:
        #             results[server] = cache.get(cache_id, False)
        #     time.sleep(1)
        for server in results:
            if results[server] is False:
                results[server] = dict(tls_enabled=False, could_not_test_smtp_starttls=True)
    except SoftTimeLimitExceeded:
        log.debug("Soft time limit exceeded.")
        for server in results:
            if results[server] is False:
                results[server] = dict(tls_enabled=False, could_not_test_smtp_starttls=True)
    return ("smtp_starttls", results)


def check_mail_tls(server, dane_cb_data, task):
    """
    Perform all the TLS related checks for this mail server in series.

    """
    # TODO: SNI?
    # send_SNI = dane_cb_data.get("data") and dane_cb_data.get("secure")
    scan = ServerScanRequest(
        server_location=ServerNetworkLocation(hostname=server, port=25),
        network_configuration=ServerNetworkConfiguration(
            tls_server_name_indication=server, tls_opportunistic_encryption=ProtocolWithOpportunisticTlsEnum.SMTP
        ),
        scan_commands=SSLYZE_SCAN_COMMANDS,
    )
    try:
        all_suites, result = run_sslyze(scan, dane_cb_data, connection_limit=1)
    except TLSException as exc:
        log.info(f"sslyze scan for mail on {server} failed: {exc}")
        return dict(server_reachable=False, tls_enabled=False)

    prots_accepted = [suites.result.tls_version_used for suites in all_suites if suites.result.is_tls_version_supported]
    ciphers_accepted = [cipher for suites in all_suites for cipher in suites.result.accepted_cipher_suites]

    prots_bad, prots_phase_out, prots_good, prots_sufficient, prots_score = evaluate_tls_protocols(prots_accepted)
    dh_param, ec_param, fs_bad, fs_phase_out, fs_score = evaluate_tls_fs_params(ciphers_accepted)
    ciphers_bad, ciphers_phase_out, ciphers_score = evaluate_tls_ciphers(ciphers_accepted)

    # Check the certificates.
    cert_results = cert_checks(server, ChecksMode.MAIL, task, dane_cb_data)

    # HACK for DANE-TA(2) and hostname mismatch!
    # Give a good hosmatch score if DANE-TA *is not* present.
    if cert_results["tls_cert"] and not has_daneTA(cert_results["dane_records"]) and cert_results["hostmatch_bad"]:
        cert_results["hostmatch_score"] = scoring.MAIL_TLS_HOSTMATCH_GOOD

    results = dict(
        tls_enabled=True,
        tls_enabled_score=scoring.MAIL_TLS_STARTTLS_EXISTS_GOOD,
        prots_bad=prots_bad,
        prots_phase_out=prots_phase_out,
        prots_good=prots_good,
        prots_sufficient=prots_sufficient,
        prots_score=prots_score,
        ciphers_bad=ciphers_bad,
        ciphers_phase_out=ciphers_phase_out,
        ciphers_score=ciphers_score,
        # TODO, currently unsupported
        cipher_order_score=scoring.WEB_TLS_CIPHER_ORDER_OK,
        cipher_order=CipherOrderStatus.na,
        cipher_order_violation=[],
        secure_reneg=result.scan_result.session_renegotiation.result.supports_secure_renegotiation,
        secure_reneg_score=(
            scoring.WEB_TLS_SECURE_RENEG_GOOD
            if result.scan_result.session_renegotiation.result.supports_secure_renegotiation
            else scoring.WEB_TLS_SECURE_RENEG_BAD
        ),
        client_reneg=result.scan_result.session_renegotiation.result.is_vulnerable_to_client_renegotiation_dos,
        client_reneg_score=(
            scoring.WEB_TLS_CLIENT_RENEG_BAD
            if result.scan_result.session_renegotiation.result.is_vulnerable_to_client_renegotiation_dos
            else scoring.WEB_TLS_CLIENT_RENEG_GOOD
        ),
        compression=result.scan_result.tls_compression.result.supports_compression,
        compression_score=(
            scoring.WEB_TLS_COMPRESSION_BAD
            if result.scan_result.tls_compression.result.supports_compression
            else scoring.WEB_TLS_COMPRESSION_GOOD
        ),
        dh_param=dh_param,
        ecdh_param=ec_param,
        fs_bad=list(fs_bad),
        fs_phase_out=list(fs_phase_out),
        fs_score=fs_score,
        zero_rtt=(
            ZeroRttStatus.bad
            if result.scan_result.tls_1_3_early_data.result.supports_early_data
            else ZeroRttStatus.good
        ),
        zero_rtt_score=(
            scoring.WEB_TLS_ZERO_RTT_BAD
            if result.scan_result.tls_1_3_early_data.result.supports_early_data
            else scoring.WEB_TLS_ZERO_RTT_GOOD
        ),
        # TODO appears to be currently unsupported
        kex_hash_func=KexHashFuncStatus.good,
        kex_hash_func_score=scoring.WEB_TLS_KEX_HASH_FUNC_OK,
    )
    results.update(cert_results)
    log.debug(f"sslyze scan for mail on {server} result: {result}")
    return results


def has_daneTA(tlsa_records):
    """
    Check if any of the TLSA records is of type DANE-TA(2).

    """
    for tlsa in tlsa_records:
        if tlsa.startswith("2"):
            return True
    return False


def check_web_tls(url, af_ip_pair=None, *args, **kwargs):
    """
    Check the webserver's TLS configuration.

    """
    scan = ServerScanRequest(
        server_location=ServerNetworkLocation(hostname=url, ip_address=af_ip_pair[1]),
        scan_commands=SSLYZE_SCAN_COMMANDS,
    )
    try:
        all_suites, result = run_sslyze(scan, None, connection_limit=25)
    except TLSException as exc:
        log.info(f"sslyze scan for web on {url} failed: {exc}")
        return dict(server_reachable=False, tls_enabled=False)

    prots_accepted = [suites.result.tls_version_used for suites in all_suites if suites.result.is_tls_version_supported]
    ciphers_accepted = [cipher for suites in all_suites for cipher in suites.result.accepted_cipher_suites]

    prots_bad, prots_phase_out, prots_good, prots_sufficient, prots_score = evaluate_tls_protocols(prots_accepted)
    dh_param, ec_param, fs_bad, fs_phase_out, fs_score = evaluate_tls_fs_params(ciphers_accepted)
    ciphers_bad, ciphers_phase_out, ciphers_score = evaluate_tls_ciphers(ciphers_accepted)

    ocsp_status = (
        OcspStatus.good
        if True  # TODO: any([d.ocsp_response_is_trusted for d in result.scan_result.certificate_info.result.certificate_deployments])
        else OcspStatus.ok
    )
    probe_result = dict(
        tls_enabled=True,
        prots_bad=prots_bad,
        prots_phase_out=prots_phase_out,
        prots_good=prots_good,
        prots_sufficient=prots_sufficient,
        prots_score=prots_score,
        ciphers_bad=ciphers_bad,
        ciphers_phase_out=ciphers_phase_out,
        ciphers_score=ciphers_score,
        # TODO, currently unsupported
        cipher_order_score=scoring.WEB_TLS_CIPHER_ORDER_OK,
        cipher_order=CipherOrderStatus.na,
        cipher_order_violation=[],
        secure_reneg=result.scan_result.session_renegotiation.result.supports_secure_renegotiation,
        secure_reneg_score=(
            scoring.WEB_TLS_SECURE_RENEG_GOOD
            if result.scan_result.session_renegotiation.result.supports_secure_renegotiation
            else scoring.WEB_TLS_SECURE_RENEG_BAD
        ),
        client_reneg=result.scan_result.session_renegotiation.result.is_vulnerable_to_client_renegotiation_dos,
        client_reneg_score=(
            scoring.WEB_TLS_CLIENT_RENEG_BAD
            if result.scan_result.session_renegotiation.result.is_vulnerable_to_client_renegotiation_dos
            else scoring.WEB_TLS_CLIENT_RENEG_GOOD
        ),
        compression=result.scan_result.tls_compression.result.supports_compression,
        compression_score=(
            scoring.WEB_TLS_COMPRESSION_BAD
            if result.scan_result.tls_compression.result.supports_compression
            else scoring.WEB_TLS_COMPRESSION_GOOD
        ),
        dh_param=dh_param,
        ecdh_param=ec_param,
        fs_bad=list(fs_bad),
        fs_phase_out=list(fs_phase_out),
        fs_score=fs_score,
        zero_rtt=(
            ZeroRttStatus.bad
            if result.scan_result.tls_1_3_early_data.result.supports_early_data
            else ZeroRttStatus.good
        ),
        zero_rtt_score=(
            scoring.WEB_TLS_ZERO_RTT_BAD
            if result.scan_result.tls_1_3_early_data.result.supports_early_data
            else scoring.WEB_TLS_ZERO_RTT_GOOD
        ),
        # TODO make sure this uses the same trust store
        ocsp_stapling=ocsp_status,
        ocsp_stapling_score=(
            scoring.WEB_TLS_OCSP_STAPLING_GOOD if ocsp_status == OcspStatus.good else scoring.WEB_TLS_OCSP_STAPLING_BAD
        ),
        # TODO appears to be currently unsupported
        kex_hash_func=KexHashFuncStatus.good,
        kex_hash_func_score=scoring.WEB_TLS_KEX_HASH_FUNC_OK,
    )
    log.debug(f"sslyze scan for web on {url} result: {probe_result}")
    return probe_result


def run_sslyze(scan, dane_cb_data, connection_limit):
    log.debug(f"starting sslyze scan for {scan.server_location}")
    scanner = Scanner(per_server_concurrent_connections_limit=connection_limit)
    scanner.queue_scans([scan])
    result = next(scanner.get_results())
    log.info(f"sslyze scan for {result.server_location} status result {result.scan_status}")
    if result.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
        raise TLSException("could not connect")
        # return dict(tls_enabled=False) ??? # TODO could_not_test_smtp_starttls ???
    all_suites = [
        result.scan_result.ssl_2_0_cipher_suites,
        result.scan_result.ssl_3_0_cipher_suites,
        result.scan_result.tls_1_0_cipher_suites,
        result.scan_result.tls_1_1_cipher_suites,
        result.scan_result.tls_1_2_cipher_suites,
        result.scan_result.tls_1_3_cipher_suites,
    ]
    for suite in all_suites:
        if suite.error_trace:
            msg = str(suite.error_trace)
            raise TLSException(msg)
    return all_suites, result


def evaluate_tls_protocols(prots_accepted: List[TlsVersionEnum]):
    prots_good = []
    prots_sufficient = []
    prots_bad = []
    prots_phase_out = []
    prots_score = scoring.WEB_TLS_PROTOCOLS_GOOD

    prot_test_configs = {
        TlsVersionEnum.TLS_1_3: ("TLS 1.3", prots_good, scoring.WEB_TLS_PROTOCOLS_GOOD),
        TlsVersionEnum.TLS_1_2: ("TLS 1.2", prots_sufficient, scoring.WEB_TLS_PROTOCOLS_GOOD),
        TlsVersionEnum.TLS_1_1: ("TLS 1.1", prots_phase_out, scoring.WEB_TLS_PROTOCOLS_GOOD),
        TlsVersionEnum.TLS_1_0: ("TLS 1.0", prots_phase_out, scoring.WEB_TLS_PROTOCOLS_GOOD),
        TlsVersionEnum.SSL_3_0: ("SSL 3.0", prots_bad, scoring.WEB_TLS_PROTOCOLS_BAD),
        TlsVersionEnum.SSL_2_0: ("SSL 2.0", prots_bad, scoring.WEB_TLS_PROTOCOLS_BAD),
    }
    for prot_accepted in prots_accepted:
        name, target_list, score = prot_test_configs[prot_accepted]
        target_list.append(name)
        prots_score = min(prots_score, score)

    return prots_bad, prots_phase_out, prots_good, prots_sufficient, prots_score


def evaluate_tls_fs_params(ciphers_accepted: List[CipherSuiteAcceptedByServer]):
    dh_sizes = [
        suite.ephemeral_key.size
        for suite in ciphers_accepted
        if suite.ephemeral_key and suite.ephemeral_key.type == OpenSslEvpPkeyEnum.DH
    ]
    dh_param = max(dh_sizes) if dh_sizes else None
    ec_sizes = [
        suite.ephemeral_key.size
        for suite in ciphers_accepted
        if suite.ephemeral_key and suite.ephemeral_key.type == OpenSslEvpPkeyEnum.EC
    ]
    ec_param = max(ec_sizes) if ec_sizes else None

    fs_bad = set()
    fs_phase_out = set()
    for suite in ciphers_accepted:
        key = suite.ephemeral_key
        if not key:
            continue
        if isinstance(key, EcDhEphemeralKeyInfo):
            if key.size < ECDH_MIN_KEY_SIZE:
                fs_bad.add(f"ECDH-{key.size}")
            if key.curve in EC_PHASE_OUT:
                fs_phase_out.add(f"ECDH-{key.curve_name}")
            elif key.curve not in EC_GOOD:
                print(key.curve)
                print(EC_GOOD)
                fs_bad.add(f"ECDH-{key.curve_name}")
        if isinstance(key, DhEphemeralKeyInfo):
            if key.size < DH_MIN_KEY_SIZE:
                fs_bad.add(f"DH-{key.size}")
            if key.generator == FFDHE_GENERATOR:
                if key.prime == FFDHE2048_PRIME:
                    fs_phase_out.add("FFDHE-2048")
                elif key.prime not in FFDHE_SUFFICIENT_PRIMES:
                    fs_bad.add(f"DH-{key.size}")
    fs_score = scoring.WEB_TLS_FS_BAD if fs_bad else scoring.WEB_TLS_FS_OK
    return dh_param, ec_param, fs_bad, fs_phase_out, fs_score


def evaluate_tls_ciphers(ciphers_accepted: List[CipherSuiteAcceptedByServer]):
    ciphers_bad = []
    ciphers_phase_out = []
    for suite in ciphers_accepted:
        # TODO: remove IANA name, just here for debugging now
        if suite.cipher_suite.name in CIPHERS_PHASE_OUT:
            ciphers_phase_out.append(f"{suite.cipher_suite.openssl_name} ({suite.cipher_suite.name})")
        if suite.cipher_suite.name not in CIPHERS_GOOD + CIPHERS_SUFFICIENT + CIPHERS_PHASE_OUT:
            ciphers_bad.append(f"{suite.cipher_suite.openssl_name} ({suite.cipher_suite.name})")
    ciphers_score = scoring.WEB_TLS_SUITES_BAD if ciphers_bad else scoring.WEB_TLS_SUITES_GOOD
    return ciphers_bad, ciphers_phase_out, ciphers_score


def do_web_http(af_ip_pairs, url, task, *args, **kwargs):
    """
    Start all the HTTP related checks for the web test.

    """
    try:
        results = {}
        for af_ip_pair in af_ip_pairs:
            results[af_ip_pair[1]] = http_checks(af_ip_pair, url, task)

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


def http_checks(af_ip_pair, url, task):
    """
    Perform the HTTP header and HTTPS redirection checks for this webserver.

    """
    forced_https_score, forced_https = forced_http_check(af_ip_pair, url, task)
    header_checkers = [
        HeaderCheckerContentEncoding(),
        HeaderCheckerStrictTransportSecurity(),
    ]
    header_results = http_headers_check(af_ip_pair, url, header_checkers, task)

    results = {
        "forced_https": forced_https,
        "forced_https_score": forced_https_score,
    }
    results.update(header_results)
    return results


def forced_http_check(af_ip_pair, url, task):
    """
    Check if the webserver is properly configured with HTTPS redirection.
    """
    try:
        http_get_ip(hostname=url, ip=af_ip_pair[1], port=443, https=True)
    except requests.RequestException:
        # No HTTPS connection available to our HTTP client.
        # Could also be too outdated config (#1130)
        return scoring.WEB_TLS_FORCED_HTTPS_BAD, ForcedHttpsStatus.no_https

    try:
        response_http = http_get_ip(hostname=url, ip=af_ip_pair[1], port=80, https=False)
    except requests.RequestException:
        # No plain HTTP available, but HTTPS is
        return scoring.WEB_TLS_FORCED_HTTPS_NO_HTTP, ForcedHttpsStatus.no_http

    forced_https = ForcedHttpsStatus.bad
    forced_https_score = scoring.WEB_TLS_FORCED_HTTPS_BAD

    for response in response_http.history[1:] + [response_http]:
        if response.url:
            parsed_url = urlparse(response.url)
            # Requirement: in case of redirecting, a domain should firstly upgrade itself by
            # redirecting to its HTTPS version before it may redirect to another domain (#1208)
            if parsed_url.scheme == "https" and url == parsed_url.hostname:
                forced_https = ForcedHttpsStatus.good
                forced_https_score = scoring.WEB_TLS_FORCED_HTTPS_GOOD
            break

    return forced_https_score, forced_https
