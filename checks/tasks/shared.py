# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
import http.client
import re
import socket
import ssl
import time
from collections import defaultdict
from urllib.parse import urlparse

from celery import shared_task
from django.conf import settings
import unbound

from . import SetupUnboundContext
from .. import batch_shared_task
from ..scoring import STATUS_MAX, ORDERED_STATUSES, STATUS_NOT_TESTED
from ..scoring import STATUS_SUCCESS, STATUS_GOOD_NOT_TESTED


# Increase http.client's _MAXHEADERS from 100 to 200.
# We had problems with a site that uses too many 'Link' headers.
http.client._MAXHEADERS = 200

MAX_MAILSERVERS = 10
MAX_REDIRECT_DEPTH = 8

# Maximum number of tries on failure to establish a connection.
# Useful with servers slow to establish first connection. (slow stateful
# firewalls?, slow spawning of threads/processes to handle the request?).
MAX_TRIES = 2

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
    addrs = []
    ip4 = self.resolve(qname, unbound.RR_TYPE_A)
    if len(ip4) > 0:
        addrs.append((socket.AF_INET, ip4[0]))
    ip6 = self.resolve(qname, unbound.RR_TYPE_AAAA)
    if len(ip6) > 0:
        addrs.append((socket.AF_INET6, ip6[0]))
    return addrs


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
            report[test_item]['tech_data'] = []
            for server, subreport in subreports.items():
                substatus = subreport[test_item]['status']
                subworststatus = subreport[test_item]['worst_status']
                if ORDERED_STATUSES[substatus] <= ORDERED_STATUSES[status]:
                    status = substatus
                    worst_status = subworststatus
                    verdict = subreport[test_item]['verdict']
                    report[test_item]['status'] = status
                    report[test_item]['worst_status'] = worst_status
                    report[test_item]['verdict'] = verdict

                if (subreport[test_item]['tech_type'] and
                        not report[test_item]['tech_type']):
                    tech_type = subreport[test_item]['tech_type']
                    report[test_item]['tech_type'] = tech_type

                data = (server, subreport[test_item]['tech_data'])
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


class NoIpError(Exception):
    pass


def socket_af(host, port, af, task, timeout=10):
    if af == socket.AF_INET6:
        ips = task.resolve(host, unbound.RR_TYPE_AAAA)
    else:
        ips = task.resolve(host, unbound.RR_TYPE_A)

    err = None
    for ip in ips:
        s = None
        try:
            s = socket.socket(af, socket.SOCK_STREAM, 0)
            s.settimeout(timeout)
            s.connect((ip, port))
            return (ip, port), s
        except socket.error as e:
            err = e
            if s is not None:
                s.close()
    if err is not None:
        raise err
    else:
        raise NoIpError()


class SetSockConnection(http.client.HTTPConnection):
    def __init__(
            self, host, port=None, timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
            source_address=None, socket_af=socket.AF_INET, task=None,
            addr=None):
        http.client.HTTPConnection.__init__(
            self, host, port, timeout, source_address)
        self.socket_af = socket_af
        self._task = task
        self.addr = addr
        self.port = port
        self.timeout = timeout
        self.compression_accepted = None

    def _create_conn(self):
        if self.addr:
            try:
                s = socket.socket(self.socket_af, socket.SOCK_STREAM, 0)
                s.settimeout(self.timeout)
                s.connect((self.addr, self.port))
                return s
            except socket.error as err:
                if s is not None:
                    s.close()
                raise err
        else:
            (addr, port), s = socket_af(
                self.host, self.port, self.socket_af, self._task, self.timeout)
            self.addr = addr
            self.port = port
            return s

    def connect(self):
        self.sock = self._create_conn()


class SetSockTLSConnection(SetSockConnection):
    default_port = 443

    def __init__(
            self, host, port=None, key_file=None, cert_file=None,
            timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
            source_address=None, socket_af=socket.AF_INET, task=None,
            addr=None):
        SetSockConnection.__init__(
            self, host=host, port=port, timeout=timeout, socket_af=socket_af,
            source_address=source_address, task=task, addr=addr)
        self.key_file = key_file
        self.cert_file = cert_file
        try:
            self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            # Connect with all ciphers (except eNULL) for HTTPS checks.
            # Proper TLS checks are not using this class.
            self.ssl_context.set_ciphers("ALL")
        except AttributeError:
            # SSLContext is only available in python >= 2.7.9
            # continue without context (and without SNI!), useful
            # for local development, prod environment must run
            # with SSLContext.
            self.ssl_context = None

    def connect(self):
        sock = self._create_conn()
        if self.ssl_context:
            # Preferred option, possiblility to set SNI
            self.sock = self.ssl_context.wrap_socket(sock,
                                                     server_hostname=self.host)
        else:
            # Backward-compitibility mode, no SNI
            self.sock = ssl.wrap_socket(sock, self.key_file, self.cert_file)


def http_fetch(
        host, af=socket.AF_INET, path="/", port=80, http_method="GET",
        task=None, depth=0, addr=None, put_headers=[], ret_headers=None,
        needed_headers=[], ret_visited_hosts=None,
        keep_conn_open=False):
    if path == "":
        path = "/"

    tries_left = MAX_TRIES
    timeout = 10
    while tries_left > 0:
        try:
            if port == 443:
                conn = SetSockTLSConnection(
                    host, port=port, socket_af=af, task=task, timeout=timeout)
            else:
                conn = SetSockConnection(
                    host, port=port, socket_af=af, task=task, timeout=timeout)
            conn.putrequest(http_method, path, skip_accept_encoding=True)
            # Must specify User-Agent. Some webservers return error otherwise.
            conn.putheader("User-Agent", "internetnl/1.0")
            # Set headers (eg for HTTP-compression test)
            for k, v in put_headers:
                conn.putheader(k, v)
            conn.endheaders()
            res = conn.getresponse()
            if not keep_conn_open:
                conn.close()
            break
        # If we could not connect we can try again.
        except socket.error as e:
            try:
                conn.close()
            except Exception:
                pass
            tries_left -= 1
            if tries_left <= 0:
                raise e
            time.sleep(1)
        # If we got another exception just raise it.
        except Exception as e:
            try:
                conn.close()
            except Exception:
                pass
            raise e

    if not ret_headers:
        ret_headers = {}
    if port not in ret_headers:
        ret_headers[port] = []
    for nh in needed_headers:
        ret_headers[port].append((nh, res.getheader(nh)))

    if not ret_visited_hosts:
        ret_visited_hosts = {}
    if port not in ret_visited_hosts:
        ret_visited_hosts[port] = []
    ret_visited_hosts[port].append(host)

    # Follow redirects, MAX_REDIRECT_DEPTH times to prevent infloop.
    if (300 <= res.status < 400 and depth < MAX_REDIRECT_DEPTH
            and res.getheader('location')):
        u = urlparse(res.getheader('location'))
        if u.scheme == 'https':
            port = 443
        if u.netloc != "":
            host = u.netloc
        host = host.split(":")[0]
        path = u.path
        if not path.startswith('/'):
            path = '/' + path
        # If the connection was not closed earlier, close it.
        if keep_conn_open:
            conn.close()
        depth += 1
        return http_fetch(
            host, af=af, path=path, port=port,
            http_method=http_method, task=task, depth=depth,
            ret_headers=ret_headers,
            ret_visited_hosts=ret_visited_hosts,
            keep_conn_open=keep_conn_open)

    return conn, res, ret_headers, ret_visited_hosts
