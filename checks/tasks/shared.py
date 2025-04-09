# Copyright: 2022, ECP, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
import binascii
import re
import socket
from collections import defaultdict
from dataclasses import dataclass, field

from celery import shared_task
from django.conf import settings

import dns
from dns.exception import DNSException
from dns.rdatatype import RdataType
from dns.resolver import NXDOMAIN, NoAnswer, NoNameservers, LifetimeTimeout

from checks.models import MxStatus
from checks.resolver import (
    dns_resolve_spf,
    dns_resolve_a,
    dns_resolve_aaaa,
    DNSSECStatus,
    dns_resolve_tlsa,
    dns_resolve_ns,
    dns_resolve_mx,
    dns_resolve,
)
from checks.tasks.spf_parser import parse as spf_parse
from checks.scoring import ORDERED_STATUSES, STATUS_MAX
from interface import batch_shared_task

MAX_MAILSERVERS = 10
MX_LOCALHOST_RE = re.compile(r"^localhost\.?$")
EMAIL_RE = re.compile(r"^[^@]+@[^@]+$")
EMAIL_MAX_LEN = 254

root_fingerprints = None
with open(settings.CA_FINGERPRINTS) as f:
    root_fingerprints = f.read().splitlines()


@shared_task(
    bind=True,
    soft_time_limit=settings.SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.SHARED_TASK_TIME_LIMIT_HIGH,
)
def mail_get_servers(self, url, *args, **kwargs):
    return do_mail_get_servers(self, url, *args, **kwargs)


@batch_shared_task(
    bind=True,
    soft_time_limit=settings.BATCH_SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.BATCH_SHARED_TASK_TIME_LIMIT_HIGH,
)
def batch_mail_get_servers(self, url, *args, **kwargs):
    return do_mail_get_servers(self, url, *args, **kwargs)


@shared_task(
    bind=True,
    soft_time_limit=settings.SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.SHARED_TASK_TIME_LIMIT_HIGH,
)
def resolve_a_aaaa(self, qname, *args, **kwargs):
    return do_resolve_single_a_aaaa(qname)


@batch_shared_task(
    bind=True,
    soft_time_limit=settings.BATCH_SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.BATCH_SHARED_TASK_TIME_LIMIT_HIGH,
)
def batch_resolve_a_aaaa(self, qname, *args, **kwargs):
    return do_resolve_single_a_aaaa(qname)


@shared_task(
    bind=True,
    soft_time_limit=settings.SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.SHARED_TASK_TIME_LIMIT_HIGH,
)
def resolve_all_a_aaaa(self, qname, *args, **kwargs):
    return do_resolve_all_a_aaaa(qname)


@batch_shared_task(
    bind=True,
    soft_time_limit=settings.BATCH_SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.BATCH_SHARED_TASK_TIME_LIMIT_HIGH,
)
def batch_resolve_all_a_aaaa(self, qname, *args, **kwargs):
    return do_resolve_all_a_aaaa(qname)


@shared_task(
    bind=True,
    soft_time_limit=settings.SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.SHARED_TASK_TIME_LIMIT_HIGH,
)
def resolve_mx(self, qname, *args, **kwargs):
    return do_resolve_mx_ips(self, qname, *args, **kwargs)


@batch_shared_task(
    bind=True,
    soft_time_limit=settings.BATCH_SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.BATCH_SHARED_TASK_TIME_LIMIT_HIGH,
)
def batch_resolve_mx(self, qname, *args, **kwargs):
    return do_resolve_mx_ips(self, qname, *args, **kwargs)


@shared_task(
    bind=True,
    soft_time_limit=settings.SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.SHARED_TASK_TIME_LIMIT_HIGH,
)
def resolve_ns(self, qname, *args, **kwargs):
    return do_resolve_ns_ips(qname)


@batch_shared_task(
    bind=True,
    soft_time_limit=settings.BATCH_SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.BATCH_SHARED_TASK_TIME_LIMIT_HIGH,
)
def batch_resolve_ns(self, qname, *args, **kwargs):
    return do_resolve_ns_ips(qname)


def do_mail_get_servers(self, url, *args, **kwargs):
    """
    Resolve the domain's mailservers and TLSA records.
    Returns [mailserver, dane_data, MxStatus].

    """
    mailservers = []
    mxlist = dns_resolve_mx(url)

    for rdata, prio in mxlist:
        is_null_mx = prio == 0 and rdata == "."
        if is_null_mx:
            if len(mxlist) > 1:
                # Invalid NULL MX next to other MX.
                return [(None, None, MxStatus.null_mx_with_other_mx)]
            elif not do_resolve_single_a_aaaa(url):
                return [(None, None, MxStatus.null_mx_without_a_aaaa)]
            return [(None, None, MxStatus.null_mx)]

        rdata = rdata.lower().strip()
        if rdata == "":
            rdata = "."
        elif re.match(MX_LOCALHOST_RE, rdata):
            # Ignore "localhost".
            continue
        dane_cb_data = resolve_dane(25, rdata)
        mailservers.append((rdata, dane_cb_data, MxStatus.has_mx))

    if not mailservers:
        if do_resolve_single_a_aaaa(url):
            try:
                spf_data = dns_resolve_spf(url)
                if spf_data:
                    spf_parsed = spf_parse(spf_data)
                    if spf_parsed.get("terms", []) == ["-all"]:
                        return [(None, None, MxStatus.no_null_mx)]
            except DNSException:
                pass
        return [(None, None, MxStatus.no_mx)]

    # Sort the mailservers on their name so that the same ones are tested for
    # all related tests.
    mailservers = sorted(mailservers, key=lambda x: x[0])[:MAX_MAILSERVERS]
    return mailservers


def get_mail_servers_mxstatus(mailservers):
    return mailservers[0][2]


def do_resolve_single_a_aaaa(qname):
    """Resolve A and AAAA records and return a single result for each type."""
    af_ip_pairs = []
    try:
        ip4 = dns_resolve_a(qname)
    except (NoAnswer, NXDOMAIN, LifetimeTimeout, dns.name.EmptyLabel):
        ip4 = []
    if len(ip4) > 0:
        af_ip_pairs.append((socket.AF_INET, ip4[0]))
    try:
        ip6 = dns_resolve_aaaa(qname)
    except (NoAnswer, NXDOMAIN, LifetimeTimeout, dns.name.EmptyLabel):
        ip6 = []
    if len(ip6) > 0:
        af_ip_pairs.append((socket.AF_INET6, ip6[0]))
    return af_ip_pairs


def do_resolve_all_a_aaaa(qname):
    """Resolve all A and AAAA records and return all results for each type."""
    af_ip_pairs = []
    try:
        ip4 = dns_resolve_a(qname)
    except (NoAnswer, NXDOMAIN, LifetimeTimeout, dns.name.EmptyLabel):
        ip4 = []
    for ip in ip4:
        af_ip_pairs.append((socket.AF_INET, ip))
    try:
        ip6 = dns_resolve_aaaa(qname)
    except (NoAnswer, NXDOMAIN, LifetimeTimeout, dns.name.EmptyLabel):
        ip6 = []
    for ip in ip6:
        af_ip_pairs.append((socket.AF_INET6, ip))
    return af_ip_pairs


def do_resolve_mx_ips(self, url, *args, **kwargs):
    """Resolve the domain's mailservers
    returns [(mailserver, af_ip_pairs)]
    """
    mx_ips_pairs = []

    for mx_name, _, status in do_mail_get_servers(self, url, *args, **kwargs):
        if status is not MxStatus.has_mx:
            continue

        af_ip_pairs = do_resolve_all_a_aaaa(mx_name)
        mx_ips_pairs.append((mx_name, af_ip_pairs))

    return mx_ips_pairs


def do_resolve_ns(qname: str) -> tuple[list[str], str]:
    """
    Find the nameservers responsible for this zone.
    Returns tuple of: list of NS names, hosted_zone_name i.e. zone for which NS was found.
    """
    try:
        ns_list = dns_resolve_ns(qname)
    except (NoAnswer, NXDOMAIN, LifetimeTimeout, dns.name.EmptyLabel):
        ns_list = []
    next_label = qname
    while not ns_list and "." in next_label:
        try:
            ns_list = dns_resolve_ns(next_label)
        except (NoAnswer, NXDOMAIN, LifetimeTimeout, dns.name.EmptyLabel):
            ns_list = []
        next_label = next_label[next_label.find(".") + 1 :]

    return ns_list, qname


def do_resolve_ns_ips(qname):
    """Resolve the domain's nameservers
    Returns [(nameserver, af_ip_pairs)]
    """
    ns_list, _ = do_resolve_ns(qname)

    for ns_name in ns_list:
        try:
            yield ns_name, do_resolve_all_a_aaaa(ns_name)
        except ValueError as ve:
            raise Exception(f"resolver failed on ns_name: {ns_name=} {ns_list=} {qname=} {ve=}")


def resolve_dane(port, dname, check_nxdomain=False):
    # Due to its complex use, the API of this call is backwards compatible
    qname = f"_{port}._tcp.{dname}"
    try:
        if check_nxdomain:
            rrset, dnssec_status = dns_resolve(qname, RdataType.A)
            data = [rr.address for rr in rrset]
        else:
            rrset, dnssec_status = dns_resolve_tlsa(qname)
            data = [(rr.usage, rr.selector, rr.mtype, binascii.hexlify(rr.cert).decode("ascii")) for rr in rrset]
    except NXDOMAIN:
        return {"nxdomain": True}
    except (NoAnswer, NoNameservers, LifetimeTimeout, dns.name.EmptyLabel):
        data = None
        dnssec_status = None
    return {
        "data": data,
        "bogus": dnssec_status == DNSSECStatus.BOGUS,
        "secure": dnssec_status == DNSSECStatus.SECURE,
    }


def results_per_domain(results):
    """
    Results contain data per test per domain (or IP).
    Return a dictionary that contains data per that domain (or IP) per test.

    """
    rpd = defaultdict(list)
    for testname, res in results:
        for k in res.keys():
            rpd[k].append((testname, res[k]))
    return rpd


def aggregate_subreports(subreports, report):
    """
    Aggregate the subreports of a domain (eg. for each IP address) into a final
    report for that domain.

    This makes sure that the final verdict and status of a subtest is the worst
    one.

    """
    if subreports:
        for test_item in report:
            status = STATUS_MAX
            worst_status = STATUS_MAX
            report[test_item]["tech_data"] = []
            for server, subreport in subreports.items():
                substatus = subreport[test_item]["status"]
                subworststatus = subreport[test_item]["worst_status"]
                if ORDERED_STATUSES[substatus] <= ORDERED_STATUSES[status]:
                    status = substatus
                    verdict = subreport[test_item]["verdict"]
                    report[test_item]["status"] = status
                    report[test_item]["verdict"] = verdict
                if ORDERED_STATUSES[subworststatus] <= ORDERED_STATUSES[worst_status]:
                    worst_status = subworststatus
                    report[test_item]["worst_status"] = worst_status

                if subreport[test_item]["tech_type"] and not report[test_item]["tech_type"]:
                    tech_type = subreport[test_item]["tech_type"]
                    report[test_item]["tech_type"] = tech_type

                subtechdata = subreport[test_item]["tech_data"]
                # This is a small hack to allow running CAA along with all other tests in web,
                # i.e. once per webserver IP, while it only applies once per target domain.
                # Therefore, the tech table is flattened to only include one result, and no server column.
                if subreport[test_item]["name"] in ["web_caa", "mail_caa"]:
                    report[test_item]["tech_data"] = [[row] for row in subtechdata]
                    continue
                elif subreport[test_item]["tech_type"] == "table_multi_col" and isinstance(subtechdata, list):
                    # Enable more columns in the aggregated tech table.
                    data = (server, *subtechdata)
                else:
                    data = (server, subtechdata)
                report[test_item]["tech_data"].append(data)

    else:
        for test_name, test_item in report.items():
            test_item["tech_type"] = ""


@dataclass
class TranslatableTechTableItem:
    """
    A representation of a message in a tech table, with an ID
    matching translations, and optional context variables.

    At time of introduction, this is small scope, but it is intended
    to be slowly used more widely to reduce typing ambiguity.
    """

    msgid: str
    context: dict[str, str] = field(default_factory=dict)

    def __repr__(self):
        return f"TTTI({self.msgid}, {self.context})"

    def to_dict(self):
        return {"msgid": self.msgid, "context": self.context}


def validate_email(email: str) -> bool:
    """
    Validate an email address, based on max length and an RE.
    Goal is to detect cases that definitely are not an email address,
    while not rejecting obscure syntax options. Hence, simplicity.
    """
    if len(email) > EMAIL_MAX_LEN:
        return False
    if EMAIL_RE.match(email):
        return True
    return False
