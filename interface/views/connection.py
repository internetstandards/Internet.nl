# Copyright: 2022, ECP, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
import ipaddress
import json
import socket
import re

from django import db
from django.conf import settings
from django.core.cache import cache
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.utils.translation import ugettext as _
from django_redis import get_redis_connection

import unbound
from checks.models import ASRecord, ConnectionTest, Resolver
from checks.probes import Probe, ProbeSet
from checks.scoring import STATUS_FAIL, STATUS_INFO, STATUS_NOT_TESTED, STATUS_NOTICE, STATUS_SUCCESS
from checks.tasks.routing import TeamCymruIPtoASN, BGPSourceUnavailableError
from interface import redis_id
from interface.views.shared import get_client_ip, get_javascript_retries, ub_ctx

probe_ipv6 = Probe("ipv6", "conn", scorename="ipv6", nourl=True, maxscore=100)
probe_resolver = Probe("resolver", "conn", scorename="dnssec", nourl=True, maxscore=100, reportfield="reportdnssec")

connectionprobes = ProbeSet()
connectionprobes.add(probe_ipv6, 0)
connectionprobes.add(probe_resolver, 1)


def hostname_callback(request, test_id, ns_type):
    if not cache.get(redis_id.conn_test.id.format(test_id)):
        return HttpResponse(status=500)
    if "test-ns6-signed" == ns_type.lower():
        cache_id = redis_id.conn_test_ns6.id.format(test_id)
        cache_id_ttl = redis_id.conn_test_ns6.ttl
        cache.set(cache_id, True, cache_id_ttl)
    request.test_id = test_id


def hostname_bogus_callback(request, test_id, ns_type):
    cache_id = redis_id.conn_test_bogus.id.format(test_id)
    cache_id_ttl = redis_id.conn_test_bogus.ttl
    cache.set(cache_id, True, cache_id_ttl)
    hostname_callback(request, test_id, ns_type)


# Testpage execution JSONP
def index(request):
    conn_test_domain = settings.CONN_TEST_DOMAIN

    return render(
        request,
        "connection.html",
        dict(
            pageclass="test-in-progress",
            pagetitle=_("connection pagetitle"),
            probes=connectionprobes.getset(),
            ipv6_test_addr=settings.IPV6_TEST_ADDR,
            conn_test_domain=conn_test_domain,
            javascript_retries=get_javascript_retries(),
            javascript_timeout=settings.JAVASCRIPT_TIMEOUT * 1000,
        ),
    )


def gettestid(request, *arg, **kw):
    ct = ConnectionTest()
    ct.report = init_ipv6_report()
    ct.reportdnssec = init_dnssec_report()
    ct.save()
    cache_id = redis_id.conn_test.id.format(ct.test_id)
    cache_ttl = redis_id.conn_test.ttl
    cache.set(cache_id, True, cache_ttl)
    return HttpResponse(json.dumps(dict(test_id=ct.test_id)))


def results(request, request_id):
    try:
        ct = ConnectionTest.objects.filter(test_id=request_id).get(finished=True)
    except ConnectionTest.DoesNotExist:
        return HttpResponseRedirect("/connection/")

    probereports = [
        connectionprobes["ipv6"].rated_results_by_model(ct),
        connectionprobes["resolver"].rated_results_by_model(ct),
    ]
    scores = [pr["totalscore"] for pr in probereports]
    score = max(min(sum(scores) / len(scores), 100), 0)

    return render(
        request,
        "connection-results.html",
        dict(
            addr=request_id,
            pageclass="connectiontest",
            pagetitle=_("connection pagetitle"),
            probes=probereports,
            score=score,
        ),
    )


def init_ipv6_report():
    report = {}
    report["resolver_conn"] = {
        "label": "detail conn ipv6 resolver-conn label",
        "status": STATUS_NOT_TESTED,
        "verdict": "detail verdict not-tested",
        "exp": "detail conn ipv6 resolver-conn exp",
        "tech_type": "",
        "tech_string": "",
        "tech_data": "",
    }
    report["dns_conn"] = {
        "label": "detail conn ipv6 dns-conn label",
        "status": STATUS_NOT_TESTED,
        "verdict": "detail verdict not-tested",
        "exp": "detail conn ipv6 dns-conn exp",
        "tech_type": "",
        "tech_string": "",
        "tech_data": "",
    }
    report["connection"] = {
        "label": "detail conn ipv6 connection label",
        "status": STATUS_NOT_TESTED,
        "verdict": "detail verdict not-tested",
        "exp": "detail conn ipv6 connection exp",
        "tech_type": "table",
        "tech_string": "detail conn ipv6 connection tech table",
        "tech_data": "",
    }
    report["privacy"] = {
        "label": "detail conn ipv6 privacy label",
        "status": STATUS_NOT_TESTED,
        "verdict": "detail verdict not-tested",
        "exp": "detail conn ipv6 privacy exp",
        "tech_type": "",
        "tech_string": "",
        "tech_data": "",
    }
    report["ipv4_conn"] = {
        "label": "detail conn ipv6 ipv4-conn label",
        "status": STATUS_NOT_TESTED,
        "verdict": "detail verdict not-tested",
        "exp": "detail conn ipv6 ipv4-conn exp",
        "tech_type": "table",
        "tech_string": "detail conn ipv6 ipv4-conn tech table",
        "tech_data": "",
    }
    return report


def init_dnssec_report():
    report = {}
    report["validation"] = {
        "label": "detail conn dnssec validation label",
        "status": STATUS_NOT_TESTED,
        "verdict": "detail verdict not-tested",
        "exp": "detail conn dnssec validation exp",
        "tech_type": "table",
        "tech_string": "detail conn dnssec validation tech table",
        "tech_data": "",
    }
    return report


# Save results after executing browser tests
def finished(request, request_id):
    try:
        ct = ConnectionTest.objects.filter(test_id=request_id).get(finished=False)
    except ConnectionTest.DoesNotExist:
        return HttpResponse(status=500)

    red = get_redis_connection("default")
    resolv = []
    resolv_owner = set()
    resolvers = red.smembers(redis_id.conn_test_resolvers.id.format(request_id))
    for resolver in resolvers:
        resolver = resolver.decode("ascii")
        cache_id = redis_id.conn_test_resolver_as.id.format(request_id, resolver)
        as_record = cache.get(cache_id)
        res = Resolver(
            connectiontest=ct, address=resolver, owner="", origin_as=as_record  # TODO: Migration with ASRecord?
        )
        resolv.append(resolver)
        if as_record:
            resolv_owner.add(as_record.description)
        else:
            resolv_owner.add("")

        res.save()
    resolv_owner = list(resolv_owner)
    ct.finished = True

    report = init_ipv6_report()
    reportdnssec = init_dnssec_report()
    ns6 = cache.get(redis_id.conn_test_ns6.id.format(request_id))
    if ns6:
        ct.resolv_ipv6 = True
        report["resolver_conn"]["status"] = STATUS_SUCCESS
        report["resolver_conn"]["verdict"] = "detail conn ipv6 resolver-conn verdict good"
    else:
        report["resolver_conn"]["status"] = STATUS_FAIL
        report["resolver_conn"]["verdict"] = "detail conn ipv6 resolver-conn verdict bad"

    if cache.get(redis_id.conn_test_aaaa.id.format(request_id)):
        ct.aaaa_ipv6 = True
        report["dns_conn"]["status"] = STATUS_SUCCESS
        report["dns_conn"]["verdict"] = "detail conn ipv6 dns-conn verdict good"
    else:
        report["dns_conn"]["status"] = STATUS_FAIL
        report["dns_conn"]["verdict"] = "detail conn ipv6 dns-conn verdict bad"

    v6 = cache.get(redis_id.conn_test_v6.id.format(request_id))
    if v6:
        v6["ip"] = anonymize_IP(v6.get("ip"))
        v6["reverse"] = anonymize_reverse_name(v6.get("reverse"))
        ct.ipv6_addr = v6["ip"]
        ct.ipv6_owner = ""  # TODO: Migration with ASRecord?
        asn = v6.get("asn")
        ct.ipv6_origin_as = cache.get(redis_id.conn_test_as.id.format(asn))
        ct.ipv6_reverse = v6["reverse"]

        if ct.ipv6_origin_as:
            owner = ct.ipv6_origin_as.description
        else:
            owner = ""

        if cache.get(redis_id.conn_test_v6_reach.id.format(request_id)):
            ct.addr_ipv6 = True
            report["connection"]["status"] = STATUS_SUCCESS
            report["connection"]["verdict"] = "detail conn ipv6 connection verdict good"
            report["connection"]["tech_data"] = [(v6.get("ip"), v6.get("reverse"), owner)]
        else:
            report["connection"]["status"] = STATUS_FAIL
            report["connection"]["verdict"] = "detail conn ipv6 connection verdict bad"
            report["connection"]["tech_type"] = ""

        if v6.get("mac_vendor", "false") != "false":
            ct.slaac_without_privext = True
            report["privacy"]["status"] = STATUS_NOTICE
            report["privacy"]["verdict"] = "detail conn ipv6 privacy verdict bad"
        else:
            report["privacy"]["status"] = STATUS_SUCCESS
            report["privacy"]["verdict"] = "detail conn ipv6 privacy verdict good"

    v4 = cache.get(redis_id.conn_test_v4.id.format(request_id))
    if v4:
        v4["ip"] = anonymize_IP(v4.get("ip")[:16])
        v4["reverse"] = anonymize_reverse_name(v4.get("reverse"))
        ct.ipv4_addr = v4["ip"]
        ct.ipv4_owner = ""  # TODO: Migration with ASRecord?
        asn = v4.get("asn")
        ct.ipv4_origin_as = cache.get(redis_id.conn_test_as.id.format(asn))
        ct.ipv4_reverse = v4["reverse"]

        if ct.ipv4_origin_as:
            owner = ct.ipv4_origin_as.description
        else:
            owner = ""

        report["ipv4_conn"]["status"] = STATUS_SUCCESS
        report["ipv4_conn"]["verdict"] = "detail conn ipv6 ipv4-conn verdict good"
        report["ipv4_conn"]["tech_data"] = [(v4.get("ip"), v4.get("reverse"), owner)]
    else:
        report["ipv4_conn"]["status"] = STATUS_INFO
        report["ipv4_conn"]["verdict"] = "detail conn ipv6 ipv4-conn verdict bad"
        report["ipv4_conn"]["tech_type"] = ""

    bogus = cache.get(redis_id.conn_test_bogus.id.format(request_id))
    if not bogus:
        if report["ipv4_conn"]["status"] == STATUS_SUCCESS or report["dns_conn"]["status"] == STATUS_SUCCESS:
            ct.dnssec_val = True
            reportdnssec["validation"]["status"] = STATUS_SUCCESS
            reportdnssec["validation"]["verdict"] = "detail conn dnssec validation verdict good"
            reportdnssec["validation"]["tech_data"] = [resolv_owner]
    else:
        reportdnssec["validation"]["status"] = STATUS_FAIL
        reportdnssec["validation"]["verdict"] = "detail conn dnssec validation verdict bad"
        reportdnssec["validation"]["tech_data"] = [resolv_owner]

    ct.report = report
    ct.reportdnssec = reportdnssec
    ct.save()
    return HttpResponse(
        json.dumps(
            dict(
                status="OK",
                connipv6=connectionprobes["ipv6"].rated_results_by_model(ct),
                connresolver=connectionprobes["resolver"].rated_results_by_model(ct),
            )
        )
    )


###
# Connection test helpers
###


def anonymize_reverse_name(name):
    """
    Anonymize reverse name before storing in the database.

    At most the 3 last labels are left unmasked. All the preceding labels are
    masked by using "[…]".

    """
    anonymized_name = ""
    mask = "[…]"
    if name:
        unmasked_labels = 3
        if name[-1] == ".":
            unmasked_labels += 1
        splitted = name.rsplit(".", unmasked_labels)
        splitted[0] = mask
        anonymized_name = ".".join(splitted)
    return anonymized_name


def anonymize_IP(ip):
    """
    Anonymize IP before storing in the database.

    Mask for IPv4: 16
    Mask for IPv6: 32

    """
    anonymized_ip = ""
    try:
        ip = ipaddress.ip_address(f"{ip.strip()}")
        if ip.version == 4:
            mask = "/16"
        else:
            mask = "/32"
        anonymized_ip = str(ipaddress.ip_network(f"{ip}{mask}", strict=False).network_address)
    except ValueError:
        pass
    return anonymized_ip


def find_AS_by_IP(ip):
    """
    Find (number, description) of the originating AS given an IP.

    - Creates/Updates the appropriate ASRecord model in the DB.
    - Stores the ASRecord model in cache.
    Relies heavily on the 'IP to ASN Mapping' DNS service of Team Cymru.
    http://www.team-cymru.org/IP-ASN-mapping.html#dns

    :param ip: ipv4 or ipv6 address
    :returns: AS number or None on error

    """
    try:
        asns_prefixes = TeamCymruIPtoASN.asn_prefix_pairs_for_ip(None, ip)
        (asn, _) = asns_prefixes[0]
    except (BGPSourceUnavailableError, IndexError):
        return None

    as_record = cache.get(redis_id.conn_test_as.id.format(asn))
    if not as_record:
        as_details_query = f"AS{asn}.asn.cymru.com."
        status, result = ub_ctx.resolve(as_details_query, unbound.RR_TYPE_TXT, unbound.RR_CLASS_IN)
        if status != 0 or result.nxdomain or not result.havedata:
            return None

        # The values in the TXT record are separated by '|' and the description
        # of the AS is the last value.
        txt = result.data.data[0][1:].decode("ascii")
        description = txt.split("|")[-1].strip()

        # Some ASes include their ASN in the description
        description = description.replace(asn, "").strip()

        # Filter out the Country Code at the end of the description
        l, sep, _ = description.rpartition(",")
        if l and sep:
            description = l

        try:
            as_record = ASRecord.objects.get(number=int(asn))
            if as_record.description != description:
                as_record.description = description
                as_record.save()
        except ASRecord.DoesNotExist:
            as_record = ASRecord(number=int(asn), description=description)
            # The following try/except is for handling race
            # conditions; when an ASRecord is created from another
            # request just before we save this one.
            try:
                as_record.save()
            except db.IntegrityError:
                as_record = ASRecord.objects.get(number=int(asn))

        cache_id = redis_id.conn_test_as.id.format(asn)
        cache_ttl = redis_id.conn_test_as.ttl
        cache.set(cache_id, as_record, cache_ttl)

    return as_record.number


def unbound_ptr(qname):
    """
    Return the PTR records for `qname` from unbound.

    """
    status, result = ub_ctx.resolve(qname, unbound.RR_TYPE_PTR, unbound.RR_CLASS_IN)
    if status == 0 and result.havedata:
        return result.data.domain_list
    else:
        return []


def resolv_list(host, test_id):
    red = get_redis_connection("default")
    # The ns_* redis id comes from the perl nameserver.
    resolvers = red.smembers(f"ns_{host}.")

    resolver_owner = {}
    for resolver in resolvers:
        resolver = resolver.decode("ascii")
        resolv_cache_id = redis_id.conn_test_resolvers.id.format(test_id)
        resolv_cache_ttl = redis_id.conn_test_resolvers.ttl
        resolv_as_cache_id = redis_id.conn_test_resolver_as.id.format(test_id, resolver)
        resolv_as_cache_ttl = redis_id.conn_test_resolver_as.ttl
        if red.sadd(resolv_cache_id, resolver):
            red.expire(resolv_cache_id, resolv_cache_ttl)
            asn = find_AS_by_IP(resolver)
            as_record = cache.get(redis_id.conn_test_as.id.format(asn))
            cache.set(resolv_as_cache_id, as_record, resolv_as_cache_ttl)
        else:
            as_record = cache.get(resolv_as_cache_id)

        if as_record:
            resolver_owner[resolver] = as_record.description
        else:
            resolver_owner[resolver] = ""

    return resolver_owner


def jsonp(func):
    """
    Decorator for the following JSON API functions for the connection test.

    """

    def dec(request, *args, **kw):
        resp = func(request, *args, **kw)
        cb = request.GET.get("callback")
        if not cb or not re.search(r"^jQuery\d+_\d+$", cb):
            cb = ""
        resp["Content-Type"] = "application/javascript"
        resp.content = f"{cb}({resp.content.decode()})"
        return resp

    return dec


###
# JSONP API
###
@jsonp
def aaaa_ipv6(request):
    cache_id = redis_id.conn_test_aaaa.id.format(request.test_id)
    cache_ttl = redis_id.conn_test_aaaa.ttl
    cache.set(cache_id, True, cache_ttl)
    return network_ipv6(request, request.test_id)


@jsonp
def addr_ipv6(request, request_id):
    cache_id = redis_id.conn_test_v6_reach.id.format(request_id)
    cache_ttl = redis_id.conn_test_v6_reach.ttl
    cache.set(cache_id, True, cache_ttl)
    return network_ipv6(request, request_id)


def get_slaac_mac_vendor(ip):
    """
    Try to get the mac vendor out of a potential IPv6 SLAAC address with no
    privacy extensions enabled.

    """
    # Get padded mac oui of SLAAC address
    s = socket.inet_pton(socket.AF_INET6, ip)
    mac_oui = bytearray(s[8:13])
    # flip 7th bit of 1st byte
    mac_oui[0] = mac_oui[0] ^ 2
    mac_oui = mac_oui.hex().upper()

    red = get_redis_connection("default")
    mac_vendor = red.hget(redis_id.padded_macs.id, mac_oui)
    if mac_vendor is None:
        mac_vendor = "false"
    else:
        mac_vendor = mac_vendor.decode(errors="replace")
    return mac_vendor


def network_ipv6(request, test_id: int = 0):
    # Normally this test can only be reached via an AAAA address, which ensures that the client_ip is an IPv6 address.
    cache_id = redis_id.conn_test_v6.id.format(test_id)
    cache_ttl = redis_id.conn_test_v6.ttl
    if not cache.add(cache_id, False, cache_ttl):
        # Already have enough information, skip this
        return HttpResponse(json.dumps(dict()))
    ip = get_client_ip(request)
    asn = find_AS_by_IP(ip)

    ipv6 = ipaddress.IPv6Address(ip)
    reverse_pointer = ipv6.reverse_pointer
    ptr_list = unbound_ptr(reverse_pointer)
    reverse = ", ".join(ptr_list)

    mac_vendor = get_slaac_mac_vendor(ip)

    resolv = resolv_list(request.get_host(), test_id)

    results = dict(ip=ip, asn=asn, reverse=reverse, mac_vendor=mac_vendor)
    cache.set(cache_id, results, settings.CACHE_TTL)
    results.update(dict(resolv=resolv))
    return HttpResponse(json.dumps(results))


@jsonp
def network_ipv4(request, test_id: int = 0):
    ip = get_client_ip(request)
    asn = find_AS_by_IP(ip)

    # Overwrite the test_id using data from django-hosts.
    if hasattr(request, "test_id"):
        test_id = request.test_id

    ipv4 = ipaddress.IPv4Address(ip)
    reverse_pointer = ipv4.reverse_pointer
    ptr_list = unbound_ptr(reverse_pointer)
    reverse = ", ".join(ptr_list)
    resolv = resolv_list(request.get_host(), test_id)
    results = dict(ip=ip, asn=asn, reverse=reverse)
    cache_id = redis_id.conn_test_v4.id.format(test_id)
    cache_ttl = redis_id.conn_test_v4.ttl
    cache.set(cache_id, results, cache_ttl)
    results.update(dict(resolv=resolv))
    return HttpResponse(json.dumps(results))


@jsonp
def network_resolver(request, test_id: int = 0):
    # Overwrite the test_id using data from django-hosts.
    if hasattr(request, "test_id"):
        test_id = request.test_id

    return HttpResponse(json.dumps(dict(resolv=resolv_list(request.get_host(), test_id))))
