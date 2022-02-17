# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
import http.client
import socket
import time
from difflib import SequenceMatcher

from bs4 import BeautifulSoup
from celery import shared_task
from celery.exceptions import SoftTimeLimitExceeded
from django.conf import settings
from django.core.cache import cache
from django.db import transaction

from checks import categories, scoring
from checks.models import DomainTestIpv6, MailTestIpv6, MxDomain, MxStatus, NsDomain, WebDomain
from checks.tasks import SetupUnboundContext, dispatcher, shared
from checks.tasks.dispatcher import check_registry
from checks.tasks.tls_connection import http_fetch
from checks.tasks.tls_connection_exceptions import ConnectionHandshakeException, ConnectionSocketException, NoIpError
from interface import batch, batch_shared_task, redis_id
from interface.views.shared import pretty_domain_name
from internetnl import log
from unbound import RR_CLASS_IN, RR_TYPE_A, RR_TYPE_AAAA, RR_TYPE_NS, ub_ctx

# mapping tasks to models
model_map = dict(web=WebDomain, ns=NsDomain, mx=MxDomain)


@shared_task(bind=True)
def web_callback(self, results, addr, req_limit_id):
    category = categories.WebIpv6()
    domainipv6 = callback(results, addr, DomainTestIpv6(), "domaintestipv6", category)
    # Always calculate scores on saving.
    from checks.probes import web_probe_ipv6

    web_probe_ipv6.rated_results_by_model(domainipv6)
    dispatcher.post_callback_hook(req_limit_id, self.request.id)
    return results


@batch_shared_task(bind=True)
def batch_web_callback(self, results, addr):
    category = categories.WebIpv6()
    domainipv6 = callback(results, addr, DomainTestIpv6(), "domaintestipv6", category)
    # Always calculate scores on saving.
    from checks.probes import batch_web_probe_ipv6

    batch_web_probe_ipv6.rated_results_by_model(domainipv6)
    batch.scheduler.batch_callback_hook(domainipv6, self.request.id)


@shared_task(bind=True)
def mail_callback(self, results, addr, req_limit_id):
    category = categories.MailIpv6()
    mailipv6 = callback(results, addr, MailTestIpv6(), "mailtestipv6", category)
    # Always calculate scores on saving.
    from checks.probes import mail_probe_ipv6

    mail_probe_ipv6.rated_results_by_model(mailipv6)
    dispatcher.post_callback_hook(req_limit_id, self.request.id)
    return results


@batch_shared_task(bind=True)
def batch_mail_callback(self, results, addr):
    category = categories.MailIpv6()
    mailipv6 = callback(results, addr, MailTestIpv6(), "mailtestipv6", category)
    # Always calculate scores on saving.
    from checks.probes import batch_mail_probe_ipv6

    batch_mail_probe_ipv6.rated_results_by_model(mailipv6)
    batch.scheduler.batch_callback_hook(mailipv6, self.request.id)


web_registered = check_registry("web_ipv6", web_callback)
batch_web_registered = check_registry("batch_web_ipv6", batch_web_callback)
mail_registered = check_registry("mail_ipv6", mail_callback)
batch_mail_registered = check_registry("batch_mail_ipv6", batch_mail_callback)


@mail_registered
@web_registered
@shared_task(
    bind=True,
    soft_time_limit=settings.SHARED_TASK_SOFT_TIME_LIMIT_MEDIUM,
    time_limit=settings.SHARED_TASK_TIME_LIMIT_MEDIUM,
    base=SetupUnboundContext,
)
def ns(self, url, *args, **kwargs):
    return do_ns(self, url, *args, **kwargs)


@batch_mail_registered
@batch_web_registered
@batch_shared_task(
    bind=True,
    soft_time_limit=settings.BATCH_SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.BATCH_SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext,
)
def batch_ns(self, url, *args, **kwargs):
    return do_ns(self, url, *args, **kwargs)


@mail_registered
@shared_task(
    bind=True,
    soft_time_limit=settings.SHARED_TASK_SOFT_TIME_LIMIT_MEDIUM,
    time_limit=settings.SHARED_TASK_TIME_LIMIT_MEDIUM,
    base=SetupUnboundContext,
)
def mx(self, url, *args, **kwargs):
    return do_mx(self, url, *args, **kwargs)


@batch_mail_registered
@batch_shared_task(
    bind=True,
    soft_time_limit=settings.BATCH_SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.BATCH_SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext,
)
def batch_mx(self, url, *args, **kwargs):
    return do_mx(self, url, *args, **kwargs)


@web_registered
@shared_task(
    bind=True,
    soft_time_limit=settings.SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext,
)
def web(self, url, *args, **kwargs):
    return do_web(self, url, *args, **kwargs)


@batch_web_registered
@batch_shared_task(
    bind=True,
    soft_time_limit=settings.BATCH_SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.BATCH_SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext,
)
def batch_web(self, url, *args, **kwargs):
    return do_web(self, url, *args, **kwargs)


@transaction.atomic
def callback(results, addr, parent, parent_name, category):
    log.debug(
        "Going to store ipv6 results. Results: %s, addr: %s, parent: %s, parent_name: %s, category, %s",
        results,
        addr,
        parent,
        parent_name,
        category,
    )

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
                "domain": domain,
                "score": dom.get("score"),
                "v4_good": v4_good,
                "v4_bad": v4_bad,
                "v6_good": v6_good,
                "v6_bad": v6_bad,
            }
            dm = model_map.get(testname)(**kw)
            dm.save()

            dom_addresses.append((pretty_domain_name(domain), v6_good + v6_bad, v4_good + v4_bad))

            if v6_bad:
                dom_unreachable.append((domain, v6_bad))

        if testname == "ns":
            parent.domain = addr
            parent.ns_score = result.get("score")

            if len(no_conn) + len(good_conn) == 0:
                category.subtests["ns_aaaa"].result_bad(dom_addresses)
            else:
                if len(has_aaaa) > 1:
                    category.subtests["ns_aaaa"].result_good(dom_addresses)
                else:
                    category.subtests["ns_aaaa"].result_only_one(dom_addresses)

                if dom_unreachable:
                    category.subtests["ns_reach"].result_bad(dom_unreachable)
                else:
                    category.subtests["ns_reach"].result_good()

        elif testname == "mx":
            parent.mx_score = result.get("score")
            parent.mx_status = result.get("mx_status")

            if len(no_conn) + len(good_conn) == 0:
                if len(result.get("domains")) == 0:
                    if parent.mx_status == MxStatus.no_null_mx:
                        category.subtests["mx_aaaa"].result_no_null_mx()
                    elif parent.mx_status == MxStatus.invalid_null_mx:
                        category.subtests["mx_aaaa"].result_invalid_null_mx()
                    elif parent.mx_status == MxStatus.null_mx:
                        category.subtests["mx_aaaa"].result_null_mx()
                    else:
                        category.subtests["mx_aaaa"].result_no_mailservers()
                else:
                    category.subtests["mx_aaaa"].result_bad(dom_addresses)
                    category.subtests["mx_reach"].result_not_tested_bad()

            else:
                if len(has_aaaa) == len(result.get("domains")):
                    category.subtests["mx_aaaa"].result_good(dom_addresses)
                else:
                    category.subtests["mx_aaaa"].result_bad(dom_addresses)

                if dom_unreachable:
                    category.subtests["mx_reach"].result_bad(dom_unreachable)
                else:
                    category.subtests["mx_reach"].result_good()

        elif testname == "web":
            parent.web_simhash_score = result.get("simhash_score")
            web_simhash_distance = result.get("simhash_distance")
            parent.web_simhash_distance = web_simhash_distance
            parent.web_score = result.get("score")

            if len(no_conn) + len(good_conn) == 0:
                category.subtests["web_aaaa"].result_bad(dom_addresses)
            else:
                category.subtests["web_aaaa"].result_good(dom_addresses)

                if dom_unreachable:
                    category.subtests["web_reach"].result_bad(dom_unreachable)
                else:
                    category.subtests["web_reach"].result_good()

                if len(good_conn) > 0:
                    if web_simhash_distance <= settings.SIMHASH_MAX and web_simhash_distance >= 0:
                        category.subtests["web_ipv46"].result_good()
                    elif web_simhash_distance >= 0:
                        category.subtests["web_ipv46"].result_bad()
                    else:
                        category.subtests["web_ipv46"].result_no_v4()

    parent.report = category.gen_report()
    parent.save()
    return parent


def test_ns_connectivity(ip, port, domain):
    # NS connectivity is first tried with TCP (in test_connectivity).
    # If that fails, maybe the NS is not doing TCP. As a last resort
    # (expensive) we initiate an unbound context that will ask the NS a
    # question he can't refuse.
    def ub_callback(data, status, result):
        if status != 0:
            data["result"] = False
        elif result.rcode == 2:  # SERVFAIL
            data["result"] = False
        else:
            data["result"] = True
        data["done"] = True

    ctx = ub_ctx()
    # XXX: Remove for now; inconsistency with applying settings on celery.
    # YYY: Removal caused infinite waiting on pipe to unbound. Added again.
    ctx.set_async(True)
    ctx.set_fwd(ip)
    cb_data = dict(done=False)
    try:
        retval, async_id = ctx.resolve_async(domain, cb_data, ub_callback, RR_TYPE_NS, RR_CLASS_IN)
        while retval == 0 and not cb_data["done"]:
            time.sleep(0.1)
            retval = ctx.process()
    except (SoftTimeLimitExceeded):
        if async_id:
            ctx.cancel(async_id)
        raise
    return cb_data["result"]


def test_connectivity(ips, af, sock_type, ports, is_ns, test_domain):
    log.debug("Testing connectivity on %s, on port %s, is_ns: %s, test_domain: %s" % (ips, ports, is_ns, test_domain))
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
                continue
            except socket.error:
                pass
            finally:
                if sock:
                    sock.close()

            if is_ns and test_ns_connectivity(ip, port, test_domain):
                good.add(ip)
                reachable_ports.add(port)

    bad = set(ips) - set(good)
    log.debug("Conclusion on %s:%s: good: %s, bad: %s, ports: %s" % (ips, ports, good, bad, reachable_ports))
    return list(good), list(bad), reachable_ports


def get_domain_results(
    domain, sock_type, ports, task, score_good, score_bad, score_partial, is_ns=False, test_domain=""
):
    """
    Resolve IPv4 and IPv6 addresses and check connectivity.

    """
    v6 = task.resolve(domain, RR_TYPE_AAAA)
    log.debug("V6 resolve: %s" % v6)
    v6_good, v6_bad, v6_ports = test_connectivity(v6, socket.AF_INET6, sock_type, ports, is_ns, test_domain)
    v4 = task.resolve(domain, RR_TYPE_A)
    log.debug("V4 resolve: %s" % v4)
    v4_good, v4_bad, v4_ports = test_connectivity(v4, socket.AF_INET, sock_type, ports, is_ns, test_domain)
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
        score=score,
    )


def do_mx(self, url, *args, **kwargs):
    try:
        domains = []
        mailservers = shared.do_mail_get_servers(self, url, *args, **kwargs)
        score = scoring.MAIL_IPV6_MX_CONN_FAIL
        mx_status = shared.get_mail_servers_mxstatus(mailservers)
        if mx_status != MxStatus.has_mx:
            mailservers = []

        for mailserver, _, _ in mailservers:
            # Check if we already have cached results.
            cache_id = redis_id.mail_ipv6.id.format(mailserver)
            cache_ttl = redis_id.mail_ipv6.ttl
            d = cache.get(cache_id)
            if not d:
                d = get_domain_results(
                    mailserver,
                    socket.SOCK_STREAM,
                    [25],
                    self,
                    score_good=scoring.MAIL_IPV6_MX_CONN_GOOD,
                    score_bad=scoring.MAIL_IPV6_MX_CONN_FAIL,
                    score_partial=scoring.MAIL_IPV6_MX_CONN_PARTIAL,
                )
                cache.set(cache_id, d, cache_ttl)

            score += d["score"]
            domains.append(d)

        if len(domains) > 0:
            score = float(score) / (len(domains) * scoring.MAIL_IPV6_MX_CONN_GOOD) * scoring.MAIL_IPV6_MX_CONN_GOOD
        else:
            # No MX records or NULL MX means full IPv6 score.
            score = scoring.MAIL_IPV6_MX_CONN_GOOD

    except (SoftTimeLimitExceeded):
        domains = []
        score = scoring.MAIL_IPV6_MX_CONN_FAIL

    return ("mx", dict(domains=domains, score=int(score), mx_status=mx_status))


def do_ns(self, url, *args, **kwargs):
    try:
        domains = []
        score = scoring.IPV6_NS_CONN_FAIL
        rrset = self.resolve(url, RR_TYPE_NS)
        log.debug("rrset: %s", rrset)
        next_label = url
        while not rrset and "." in next_label:
            rrset = self.resolve(next_label, RR_TYPE_NS)
            next_label = next_label[next_label.find(".") + 1 :]

        has_a = set()  # Name servers that have IPv4.
        has_aaaa = set()  # Name servers that have IPv6.
        if rrset:
            for domain in rrset:
                log.debug("Getting domain result of %s", domain)
                d = get_domain_results(
                    domain,
                    socket.SOCK_STREAM,
                    [53],
                    self,
                    score_good=scoring.IPV6_NS_CONN_GOOD,
                    score_bad=scoring.IPV6_NS_CONN_FAIL,
                    score_partial=scoring.IPV6_NS_CONN_PARTIAL,
                    is_ns=True,
                    test_domain=next_label,
                )
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
                if domain["domain"] in ipv4_only or domain["domain"] not in has_aaaa:
                    dom_len -= 1

        # For one name server give at most half the points, calculate for rest.
        if dom_len == 1:
            score = min(float(scoring.IPV6_NS_CONN_GOOD) / 2, score)
        elif dom_len > 1:
            score = float(score) / (dom_len * scoring.IPV6_NS_CONN_GOOD) * scoring.IPV6_NS_CONN_GOOD

    except SoftTimeLimitExceeded:
        log.debug("Soft time limit exceeded.")
        domains = []
        score = scoring.IPV6_NS_CONN_FAIL

    return "ns", dict(domains=domains, score=int(score))


def simhash(url, task=None):
    """
    Connect on both IPv4 and IPv6 and see if the same content is served.

    First try to connect over HTTP. If that fails for one of the addresses
    try HTTPS for both.

    It uses SequenceMatcher to compare the contents.

    """

    def strip_irrelevant_html(html):
        """
        Strip irrelevant HTML for correct comparison.

        This currently strips nonces from script and style tags.

        """
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.select(",".join([f"{t}[nonce]" for t in ("script", "style")])):
            del tag["nonce"]
        hidden_tags = soup.find_all("input", {"name": "__VIEWSTATE"})
        for tag in hidden_tags:
            tag.extract()
        try:
            return soup.prettify("latin-1")
        except RecursionError:
            return html

    simhash_score = scoring.WEB_IPV6_WS_SIMHASH_FAIL
    distance = settings.SIMHASH_MAX + 100

    v4_conn = None
    v6_conn = None
    for port in [80, 443]:
        try:
            v4_conn, v4_res, _, _ = http_fetch(url, socket.AF_INET, port=port, task=task, keep_conn_open=True)
            v6_conn, v6_res, _, _ = http_fetch(url, socket.AF_INET6, port=port, task=task, keep_conn_open=True)
            break
        except (
            socket.error,
            NoIpError,
            http.client.BadStatusLine,
            ConnectionHandshakeException,
            ConnectionSocketException,
        ):
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

    html_v4 = strip_irrelevant_html(html_v4)
    html_v6 = strip_irrelevant_html(html_v6)
    sim = SequenceMatcher(None, html_v4, html_v6)
    distance = 100 - sim.quick_ratio() * 100
    if distance <= settings.SIMHASH_MAX:
        simhash_score = scoring.WEB_IPV6_WS_SIMHASH_OK

    return simhash_score, distance


def do_web(self, url, *args, **kwargs):
    try:
        log.debug("Performing IPv6 check")
        domain = []
        simhash_score = scoring.WEB_IPV6_WS_SIMHASH_FAIL
        simhash_distance = settings.SIMHASH_MAX + 100
        score = scoring.WEB_IPV6_WS_CONN_FAIL

        domain = get_domain_results(
            url,
            socket.SOCK_STREAM,
            [80, 443],
            self,
            score_good=scoring.WEB_IPV6_WS_CONN_GOOD,
            score_bad=scoring.WEB_IPV6_WS_CONN_FAIL,
            score_partial=scoring.WEB_IPV6_WS_CONN_PARTIAL,
        )

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

    except (SoftTimeLimitExceeded):
        log.debug("Error: SoftTimeLimitExceeded")
        if not domain:
            domain = dict(
                domain=url,
                v4_good=[],
                v4_bad=[],
                v6_good=[],
                v6_bad=[],
                v6_conn_diff=[],
                score=scoring.WEB_IPV6_WS_CONN_FAIL,
            )

    return ("web", dict(domains=[domain], simhash_score=simhash_score, simhash_distance=simhash_distance, score=score))
