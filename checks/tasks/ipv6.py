# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
from difflib import SequenceMatcher
import http.client
import socket

from unbound import RR_TYPE_AAAA, RR_TYPE_A, RR_TYPE_NS

from celery import shared_task
from celery.exceptions import SoftTimeLimitExceeded
from django.conf import settings
from django.core.cache import cache
from django.db import transaction

from . import dispatcher
from . import SetupUnboundContext
from . import shared
from .tls_connection import http_fetch, NoIpError, ConnectionHandshakeException
from .tls_connection import ConnectionSocketException
from .dispatcher import check_registry
from .. import scoring, categories, redis_id
from .. import batch, batch_shared_task
from ..models import DomainTestIpv6, MailTestIpv6, MxDomain, NsDomain
from ..models import WebDomain
from ..views.shared import pretty_domain_name


# mapping tasks to models
model_map = dict(
    web=WebDomain,
    ns=NsDomain,
    mx=MxDomain)


@shared_task(bind=True)
def web_callback(self, results, addr, req_limit_id):
    category = categories.WebIpv6()
    domainipv6 = callback(
        results, addr, DomainTestIpv6(), "domaintestipv6", category)
    # Always calculate scores on saving.
    from ..probes import web_probe_ipv6
    web_probe_ipv6.rated_results_by_model(domainipv6)
    dispatcher.post_callback_hook(req_limit_id, self.request.id)
    return results


@batch_shared_task(bind=True)
def batch_web_callback(self, results, addr):
    category = categories.WebIpv6()
    domainipv6 = callback(
        results, addr, DomainTestIpv6(), "domaintestipv6", category)
    # Always calculate scores on saving.
    from ..probes import batch_web_probe_ipv6
    batch_web_probe_ipv6.rated_results_by_model(domainipv6)
    batch.scheduler.batch_callback_hook(domainipv6, self.request.id)


@shared_task(bind=True)
def mail_callback(self, results, addr, req_limit_id):
    category = categories.MailIpv6()
    mailipv6 = callback(
        results, addr, MailTestIpv6(), "mailtestipv6", category)
    # Always calculate scores on saving.
    from ..probes import mail_probe_ipv6
    mail_probe_ipv6.rated_results_by_model(mailipv6)
    dispatcher.post_callback_hook(req_limit_id, self.request.id)
    return results


@batch_shared_task(bind=True)
def batch_mail_callback(self, results, addr):
    category = categories.MailIpv6()
    mailipv6 = callback(
        results, addr, MailTestIpv6(), "mailtestipv6", category)
    # Always calculate scores on saving.
    from ..probes import batch_mail_probe_ipv6
    batch_mail_probe_ipv6.rated_results_by_model(mailipv6)
    batch.scheduler.batch_callback_hook(mailipv6, self.request.id)


web_registered = check_registry("web_ipv6", web_callback)
batch_web_registered = check_registry("batch_web_ipv6", batch_web_callback)
mail_registered = check_registry("mail_ipv6", mail_callback)
batch_mail_registered = check_registry("batch_mail_ipv6", batch_mail_callback)


@mail_registered
@web_registered
@shared_task(
    bind=True, soft_time_limit=settings.SHARED_TASK_SOFT_TIME_LIMIT_MEDIUM,
    time_limit=settings.SHARED_TASK_TIME_LIMIT_MEDIUM,
    base=SetupUnboundContext)
def ns(self, url, *args, **kwargs):
    return do_ns(self, url, *args, **kwargs)


@batch_mail_registered
@batch_web_registered
@batch_shared_task(
    bind=True, soft_time_limit=settings.BATCH_SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.BATCH_SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext)
def batch_ns(self, url, *args, **kwargs):
    return do_ns(self, url, *args, **kwargs)


@mail_registered
@shared_task(
    bind=True, soft_time_limit=settings.SHARED_TASK_SOFT_TIME_LIMIT_MEDIUM,
    time_limit=settings.SHARED_TASK_TIME_LIMIT_MEDIUM,
    base=SetupUnboundContext)
def mx(self, url, *args, **kwargs):
    return do_mx(self, url, *args, **kwargs)


@batch_mail_registered
@batch_shared_task(
    bind=True, soft_time_limit=settings.BATCH_SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.BATCH_SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext)
def batch_mx(self, url, *args, **kwargs):
    return do_mx(self, url, *args, **kwargs)


@web_registered
@shared_task(
    bind=True, soft_time_limit=settings.SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext)
def web(self, url, *args, **kwargs):
    return do_web(self, url, *args, **kwargs)


@batch_web_registered
@batch_shared_task(
    bind=True, soft_time_limit=settings.BATCH_SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.BATCH_SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext)
def batch_web(self, url, *args, **kwargs):
    return do_web(self, url, *args, **kwargs)


@transaction.atomic
def callback(results, addr, parent, parent_name, category):
    parent.report = {}
    parent.save()

    for testname, result in results:
        no_aaaa = []
        has_aaaa = []
        has_a = []
        no_conn = []
        good_conn = []
        v6_port_diff = []

        dom_addresses = []
        dom_unreachable = []
        for dom in result.get("domains"):
            domain = dom.get("domain")
            v6_port_diff.extend(dom.get("v6_conn_diff"))
            v6_good = dom.get("v6_good")
            v6_bad = dom.get("v6_bad")
            v4_good = dom.get("v4_good")
            v4_bad = dom.get("v4_bad")
            if len(v4_good) + len(v4_bad) > 0:
                has_a.append(domain)
            if len(v6_good) + len(v6_bad) == 0:
                no_aaaa.append(domain)
            else:
                has_aaaa.append(domain)
                if len(v6_good) > 0:
                    good_conn.append(domain)
                else:
                    no_conn.append(domain)

            kw = {
                parent_name: parent,
                'domain': domain,
                'score': dom.get("score"),
                'v4_good': v4_good,
                'v4_bad': v4_bad,
                'v6_good': v6_good,
                'v6_bad': v6_bad}
            dm = model_map.get(testname)(**kw)
            dm.save()

            dom_addresses.append((
                pretty_domain_name(domain),
                v6_good + v6_bad,
                v4_good + v4_bad))

            if v6_bad:
                dom_unreachable.append((domain, v6_bad))

        if testname == "ns":
            parent.domain = addr
            parent.ns_score = result.get("score")

            if len(no_conn) + len(good_conn) == 0:
                category.subtests['ns_aaaa'].result_bad(dom_addresses)
            else:
                if len(has_aaaa) > 1:
                    category.subtests['ns_aaaa'].result_good(dom_addresses)
                else:
                    category.subtests['ns_aaaa'].result_only_one(dom_addresses)

                if dom_unreachable:
                    category.subtests['ns_reach'].result_bad(dom_unreachable)
                else:
                    category.subtests['ns_reach'].result_good()

        elif testname == "mx":
            parent.mx_score = result.get("score")

            if len(no_conn) + len(good_conn) == 0:
                if len(result.get("domains")) == 0:
                    category.subtests['mx_aaaa'].result_no_mailservers()
                else:
                    category.subtests['mx_aaaa'].result_bad(dom_addresses)
                    category.subtests['mx_reach'].result_not_tested_bad()

            else:
                if len(has_aaaa) == len(result.get("domains")):
                    category.subtests['mx_aaaa'].result_good(dom_addresses)
                else:
                    category.subtests['mx_aaaa'].result_bad(dom_addresses)

                if dom_unreachable:
                    category.subtests['mx_reach'].result_bad(dom_unreachable)
                else:
                    category.subtests['mx_reach'].result_good()

        elif testname == "web":
            parent.web_simhash_score = result.get("simhash_score")
            web_simhash_distance = result.get("simhash_distance")
            parent.web_simhash_distance = web_simhash_distance
            parent.web_score = result.get("score")

            if len(no_conn) + len(good_conn) == 0:
                category.subtests['web_aaaa'].result_bad(dom_addresses)
            else:
                category.subtests['web_aaaa'].result_good(dom_addresses)

                if dom_unreachable:
                    category.subtests['web_reach'].result_bad(dom_unreachable)
                else:
                    category.subtests['web_reach'].result_good()

                if len(good_conn) > 0:
                    if (web_simhash_distance <= settings.SIMHASH_MAX
                            and web_simhash_distance >= 0):
                        category.subtests['web_ipv46'].result_good()
                    elif web_simhash_distance >= 0:
                        category.subtests['web_ipv46'].result_bad()
                    else:
                        category.subtests['web_ipv46'].result_no_v4()

    parent.report = category.gen_report()
    parent.save()
    return parent


def test_connectivity(ips, af, sock_type, ports):
    good = set()
    bad = set()
    reachable_ports = set()
    for ip in ips:
        for port in ports:
            sock = None
            try:
                sock = socket.socket(af, sock_type)
                sock.settimeout(4)
                sock.connect((ip, port))
                good.add(ip)
                reachable_ports.add(port)
                # break
            except socket.error:
                pass
            finally:
                if sock:
                    sock.close()

    bad = set(ips) - set(good)
    return list(good), list(bad), reachable_ports


def get_domain_results(
        domain, sock_type, ports, task, score_good, score_bad, score_partial):
    """
    Resolve IPv4 and IPv6 addresses and check connectivity.

    """
    v6 = task.resolve(domain, RR_TYPE_AAAA)
    v6_good, v6_bad, v6_ports = test_connectivity(
        v6, socket.AF_INET6, sock_type, ports)
    v4 = task.resolve(domain, RR_TYPE_A)
    v4_good, v4_bad, v4_ports = test_connectivity(
        v4, socket.AF_INET, sock_type, ports)
    v6_conn_diff = v4_ports - v6_ports

    score = score_good

    if len(v6_good) == 0:
        score = score_bad
    elif len(v6_bad) > 0 or len(v6_conn_diff) > 0:
        score = score_partial

    return dict(
        domain=domain,
        v4_good=v4_good,
        v4_bad=v4_bad,
        v6_good=v6_good,
        v6_bad=v6_bad,
        v6_conn_diff=list(v6_conn_diff),
        score=score)


def do_mx(self, url, *args, **kwargs):
    try:
        domains = []
        mailservers = shared.do_mail_get_servers(self, url, *args, **kwargs)
        score = scoring.MAIL_IPV6_MX_CONN_FAIL
        skipped = False
        for mailserver, _ in mailservers:
            # Check if we already have cached results.
            cache_id = redis_id.mail_ipv6.id.format(mailserver)
            cache_ttl = redis_id.mail_ipv6.ttl
            d = cache.get(cache_id)
            if not d:
                d = get_domain_results(
                    mailserver, socket.SOCK_STREAM, [25], self,
                    score_good=scoring.MAIL_IPV6_MX_CONN_GOOD,
                    score_bad=scoring.MAIL_IPV6_MX_CONN_FAIL,
                    score_partial=scoring.MAIL_IPV6_MX_CONN_PARTIAL)
                cache.set(cache_id, d, cache_ttl)

            score += d["score"]
            domains.append(d)

        if len(domains) > 0:
            score = (
                float(score) / (len(domains) * scoring.MAIL_IPV6_MX_CONN_GOOD)
                * scoring.MAIL_IPV6_MX_CONN_GOOD)
        else:
            # No MX records means full IPv6 score
            score = scoring.MAIL_IPV6_MX_CONN_GOOD
            skipped = True

    except SoftTimeLimitExceeded:
        domains = []
        score = scoring.MAIL_IPV6_MX_CONN_FAIL
        skipped = False

    return ("mx", dict(
        domains=domains,
        score=int(score),
        skipped=skipped))


def do_ns(self, url, *args, **kwargs):
    try:
        domains = []
        score = scoring.IPV6_NS_CONN_FAIL
        rrset = self.resolve(url, RR_TYPE_NS)
        next_label = url
        while not rrset and "." in next_label:
            rrset = self.resolve(next_label, RR_TYPE_NS)
            next_label = next_label[next_label.find(".")+1:]

        has_a = set()  # Name servers that have IPv4.
        has_aaaa = set()  # Name servers that have IPv6.
        if rrset:
            for domain in rrset:
                d = get_domain_results(
                    domain, socket.SOCK_DGRAM, [53], self,
                    score_good=scoring.IPV6_NS_CONN_GOOD,
                    score_bad=scoring.IPV6_NS_CONN_FAIL,
                    score_partial=scoring.IPV6_NS_CONN_PARTIAL)
                if len(d["v4_good"]) + len(d["v4_bad"]) > 0:
                    has_a.add(d["domain"])
                if len(d["v6_good"]) + len(d["v6_bad"]) > 0:
                    has_aaaa.add(d["domain"])
                score += d["score"]
                domains.append(d)
        dom_len = len(domains)
        ipv4_only = has_a - has_aaaa

        # If the number of IPv6 name servers is sufficient (at least 2), ignore
        # any IPv4-only name servers or nameservers with no addresses at all.
        if len(has_aaaa) > 1:
            for domain in domains:
                if (domain["domain"] in ipv4_only
                        or domain["domain"] not in has_aaaa):
                    dom_len -= 1

        # For one name server give at most half the points, calculate for rest.
        if dom_len == 1:
            score = min(float(scoring.IPV6_NS_CONN_GOOD) / 2, score)
        elif dom_len > 1:
            score = (
                float(score) / (dom_len * scoring.IPV6_NS_CONN_GOOD)
                * scoring.IPV6_NS_CONN_GOOD)

    except SoftTimeLimitExceeded:
        domains = []
        score = scoring.IPV6_NS_CONN_FAIL

    return ("ns", dict(
        domains=domains,
        score=int(score)))


def simhash(url, task=None):
    """
    Connect on both IPv4 and IPv6 and see if the same content is served.

    First try to connect over HTTP. If that fails for one of the addresses
    try HTTPS for both.

    It uses SequenceMatcher to compare the contents.

    """
    simhash_score = scoring.WEB_IPV6_WS_SIMHASH_FAIL
    distance = settings.SIMHASH_MAX + 100

    v4_conn = None
    v6_conn = None
    for port in [80, 443]:
        try:
            v4_conn, v4_res, _, _ = http_fetch(
                url, socket.AF_INET, port=port, task=task,
                keep_conn_open=True)
            v6_conn, v6_res, _, _ = http_fetch(
                url, socket.AF_INET6, port=port, task=task,
                keep_conn_open=True)
            break
        except (socket.error, NoIpError, http.client.BadStatusLine,
                ConnectionHandshakeException, ConnectionSocketException):
            # Could not connect on given port, try another port.
            # If we managed to connect on IPv4 however, fail the test.
            if v4_conn:
                v4_conn.close()
                return simhash_score, distance

    if not v4_conn:
        # FAIL: Could not establish a connection on both addresses.
        return simhash_score, distance

    try:
        # read max 0.5MB
        html_v4 = v4_res.read(500000)
        v4_conn.close()
        v4_conn = None

        html_v6 = v6_res.read(500000)
        v6_conn.close()
        v6_conn = None
    except (socket.error, http.client.IncompleteRead):
        if v4_conn:
            v4_conn.close()
        if v6_conn:
            v6_conn.close()
        return simhash_score, distance

    sim = SequenceMatcher(None, html_v4, html_v6)
    distance = 100 - sim.quick_ratio() * 100
    if distance <= settings.SIMHASH_MAX:
        simhash_score = scoring.WEB_IPV6_WS_SIMHASH_OK

    return simhash_score, distance


def do_web(self, url, *args, **kwargs):
    try:
        domain = []
        simhash_score = scoring.WEB_IPV6_WS_SIMHASH_FAIL
        simhash_distance = settings.SIMHASH_MAX + 100
        score = scoring.WEB_IPV6_WS_CONN_FAIL

        domain = get_domain_results(
            url, socket.SOCK_STREAM, [80, 443], self,
            score_good=scoring.WEB_IPV6_WS_CONN_GOOD,
            score_bad=scoring.WEB_IPV6_WS_CONN_FAIL,
            score_partial=scoring.WEB_IPV6_WS_CONN_PARTIAL)

        v6_good = domain["v6_good"]
        v4_good = domain["v4_good"]
        v4_bad = domain["v4_bad"]
        v6_conn_diff = domain["v6_conn_diff"]
        score = domain["score"]

        # Give points to IPv6-only domains
        if len(v6_good) > 0 and len(v4_good) == 0 and len(v4_bad) == 0:
            simhash_score = scoring.WEB_IPV6_WS_SIMHASH_OK
            simhash_distance = -1
        elif len(v6_good) > 0 and len(v4_good) > 0 and len(v6_conn_diff) == 0:
            simhash_score, simhash_distance = simhash(url, task=self)

    except SoftTimeLimitExceeded:
        if not domain:
            domain = dict(
                domain=url,
                v4_good=[],
                v4_bad=[],
                v6_good=[],
                v6_bad=[],
                v6_conn_diff=[],
                score=scoring.WEB_IPV6_WS_CONN_FAIL)

    return ("web", dict(
        domains=[domain],
        simhash_score=simhash_score,
        simhash_distance=simhash_distance,
        score=score))
