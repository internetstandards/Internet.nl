# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
import ipaddress
import inspect
import logging
import re
import socket
import time

from enum import Enum
from internetnl import celery_app
from celery import shared_task
from django.conf import settings
import unbound

from . import SetupUnboundContext
from .. import batch_shared_task
from ..scoring import STATUS_MAX, ORDERED_STATUSES, STATUS_NOT_TESTED
from ..scoring import STATUS_SUCCESS, STATUS_GOOD_NOT_TESTED

from collections import defaultdict


MAX_MAILSERVERS = 10
MX_LOCALHOST_RE = re.compile("^localhost\.?$")


root_fingerprints = None
with open(settings.CA_FINGERPRINTS) as f:
    root_fingerprints = f.read().splitlines()


@shared_task(
    bind=True,
    soft_time_limit=settings.SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext)
def mail_get_servers(self, url, *args, **kwargs):
    return do_mail_get_servers(self, url, *args, **kwargs)


@batch_shared_task(
    bind=True,
    soft_time_limit=settings.BATCH_SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.BATCH_SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext)
def batch_mail_get_servers(self, url, *args, **kwargs):
    return do_mail_get_servers(self, url, *args, **kwargs)


@shared_task(
    bind=True,
    soft_time_limit=settings.SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext)
def resolve_a_aaaa(self, qname, *args, **kwargs):
    return do_resolve_a_aaaa(self, qname, *args, **kwargs)


@batch_shared_task(
    bind=True,
    soft_time_limit=settings.BATCH_SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.BATCH_SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext)
def batch_resolve_a_aaaa(self, qname, *args, **kwargs):
    return do_resolve_a_aaaa(self, qname, *args, **kwargs)


def do_mail_get_servers(self, url, *args, **kwargs):
    # for MX for url
    mailservers = []
    mxlist = self.resolve(url, unbound.RR_TYPE_MX)
    for prio, rdata in mxlist:
        # Treat nullmx (RFC7505)
        # as "no MX available"
        is_null_mx = prio == 0 and rdata == ''
        if not is_null_mx:
            rdata = rdata.lower().strip()
            if rdata == '':
                rdata = '.'
            # Treat 'localhost' as "no MX available"
            elif re.match(MX_LOCALHOST_RE, rdata):
                continue
            dane_cb_data = resolve_dane(self, 25, rdata)
            mailservers.append((rdata, dane_cb_data))
    return mailservers[:MAX_MAILSERVERS]


def do_resolve_a_aaaa(self, qname, *args, **kwargs):
    af_ip_pairs = []
    ip4 = self.resolve(qname, unbound.RR_TYPE_A)
    if len(ip4) > 0:
        af_ip_pairs.append((socket.AF_INET, ip4[0]))
    ip6 = self.resolve(qname, unbound.RR_TYPE_AAAA)
    if len(ip6) > 0:
        af_ip_pairs.append((socket.AF_INET6, ip6[0]))
    return af_ip_pairs


def resolve_dane(task, port, dname, check_nxdomain=False):
    qname = "_{}._tcp.{}".format(port, dname)
    if check_nxdomain:
        qtype = unbound.RR_TYPE_A
        cb_data = task.async_resolv(qname, qtype)
    else:
        qtype = 52  # unbound.RR_TYPE_TLSA
        cb_data = task.resolve(qname, qtype)
    return cb_data


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

    In case of mixed 'good' and 'not_tested' results we show the good verdict
    but with the 'good_not_tested' status.

    """
    if subreports:
        for test_item in report:
            status = STATUS_MAX
            worst_status = STATUS_MAX
            report[test_item]['tech_data'] = []
            for server, subreport in subreports.items():
                substatus = subreport[test_item]['status']
                subworststatus = subreport[test_item]['worst_status']
                if ORDERED_STATUSES[substatus] <= ORDERED_STATUSES[status]:
                    status = substatus
                    verdict = subreport[test_item]['verdict']
                    report[test_item]['status'] = status
                    report[test_item]['verdict'] = verdict
                if ORDERED_STATUSES[subworststatus] <= ORDERED_STATUSES[worst_status]:
                    worst_status = subworststatus
                    report[test_item]['worst_status'] = worst_status

                if (subreport[test_item]['tech_type'] and
                        not report[test_item]['tech_type']):
                    tech_type = subreport[test_item]['tech_type']
                    report[test_item]['tech_type'] = tech_type

                subtechdata = subreport[test_item]['tech_data']
                if (subreport[test_item]['tech_multi_col'] and
                        isinstance(subtechdata, list)):
                    # support more than two columns in the tech detail table
                    data = (server, *subtechdata)
                else:
                    data = (server, subtechdata)
                report[test_item]['tech_data'].append(data)

            # If the results are 'good' and 'not_tested' mixed, we show the
            # good verdict but with the good_not_tested status.
            if (report[test_item]['status'] == STATUS_NOT_TESTED and
                any((subreport[test_item]['status'] == STATUS_SUCCESS
                    for _, subreport in subreports.items()))):
                report[test_item]['status'] = STATUS_GOOD_NOT_TESTED
                good_verdict = report[test_item]['label'].replace(
                    ' label', ' verdict good')
                report[test_item]['verdict'] = good_verdict
    else:
        for test_name, test_item in report.items():
            test_item['tech_type'] = ""
