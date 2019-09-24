# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
import http.client
import ipaddress
import inspect
import logging
import re
import socket
import time

from internetnl import celery_app
from celery import shared_task
from django.conf import settings
import unbound

from . import SetupUnboundContext
from .. import batch_shared_task
from ..scoring import STATUS_MAX, ORDERED_STATUSES, STATUS_NOT_TESTED
from ..scoring import STATUS_SUCCESS, STATUS_GOOD_NOT_TESTED
from ..views.shared import ub_resolve_with_timeout

from nassl.ssl_client import OpenSslVersionEnum, OpenSslVerifyEnum
from nassl import _nassl
from nassl.legacy_ssl_client import LegacySslClient
from nassl.ssl_client import SslClient
from nassl.ssl_client import ClientCertificateRequested
from io import BytesIO

from cgi import parse_header
from collections import defaultdict, namedtuple
from urllib.parse import urlparse


# Use a dedicated logger as this logging can be very verbose
sslConnectLogger = logging.getLogger('internetnl.ssl.connect')


SSLV23 = OpenSslVersionEnum.SSLV23
SSLV2 = OpenSslVersionEnum.SSLV2
SSLV3 = OpenSslVersionEnum.SSLV3
TLSV1 = OpenSslVersionEnum.TLSV1
TLSV1_1 = OpenSslVersionEnum.TLSV1_1
TLSV1_2 = OpenSslVersionEnum.TLSV1_2
TLSV1_3 = OpenSslVersionEnum.TLSV1_3
SSL_VERIFY_NONE = OpenSslVerifyEnum.NONE


ALL_TLS12_AND_PRE_CIPHERS = "ALL:COMPLEMENTOFALL"
# Exclude "TLS_AES_128_CCM_SHA256:TLS_AES_128_CCM_8_SHA256" as our OpenSSL 1.1.1
# doesn't support them.
ALL_TLS13_CIPHERS = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"


# Increase http.client's _MAXHEADERS from 100 to 200.
# We had problems with a site that uses too many 'Link' headers.
http.client._MAXHEADERS = 200

MAX_MAILSERVERS = 10
MAX_REDIRECT_DEPTH = 8

# Maximum number of tries on failure to establish a connection.
# Useful with servers slow to establish first connection. (slow stateful
# firewalls?, slow spawning of threads/processes to handle the request?).
MAX_TRIES = 2
DEFAULT_TIMEOUT = 10

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


class NoIpError(Exception):
    pass


def sock_connect(host, ip, port, ipv6=False, task=None,
        timeout=DEFAULT_TIMEOUT):
    """
    Connect to the specified host or IP address on the specified port.

    If no IP address is provided the host will be resolved using the Unbound
    context attached to the given task, or the current Celery worker task if no
    task is given. If the calling code isn't running as part of a Celery task
    (e.g. dmarc_fetch_public_suffix_list()) then use the global unbound context
    instance instead.

    If ipv6 is False the name will be resolved to an IPV4 address, otherwise it
    will be resolved to an IPV6 address. Timeout is a positive floating point
    number.

    Returns an (ip, socket) tuple on success.

    Raises NoIpError if the given host name cannot be resolved to an IP
    address.

    Raises OSError or a subclass thereof if unable to connect.
    """
    if ip:
        ips = [ip]
    else:
        # Resolve the name to one or more IP addresses of the correct type
        rr_type = unbound.RR_TYPE_AAAA if ipv6 else unbound.RR_TYPE_A
        task = task if task else celery_app.current_worker_task
        if task:
            ips = task.resolve(host, rr_type)
        else:
            cb_data = ub_resolve_with_timeout(host, rr_type,
                unbound.RR_CLASS_IN, timeout)
            af = socket.AF_INET6 if ipv6 else socket.AF_INET
            ips = [socket.inet_ntop(af, rr) for rr in cb_data["data"].data]
        if not ips:
            raise NoIpError(f"Unable to resolve {rr_type} record for host "
                "'{host}'")

    # Return the connection details for the first IP address that we can
    # successfully connect to.
    af = socket.AF_INET6 if ipv6 else socket.AF_INET
    try:
        for this_ip in ips:
            try:
                s = socket.socket(af, socket.SOCK_STREAM, 0)
                s.settimeout(timeout)
                s.connect((this_ip, port))
                return (this_ip, s)
            except OSError as e:
                if s:
                    s.close()
                err = e
    except Exception as e:
        raise e

    raise err


# TODO: factor out TLS test specific functionality (used in tls.py) from basic
# connectivity (used here by http_fetch and also by tls.py).
class ConnectionHandshakeException(socket.error):
    pass


class ConnectionSocketException(socket.error):
    pass


# Almost identical to HTTPConnection::_create_conn()
def plain_sock_setup(conn):
    conn.sock = None

    tries_left = conn.tries
    while tries_left > 0:
        try:
            conn.sock_connect()
            break
        except (socket.gaierror, socket.error, IOError, ConnectionRefusedError):
            conn.safe_shutdown()
            tries_left -= 1
            if tries_left <= 0:
                raise ConnectionSocketException()
            time.sleep(1)


class ConnectionCommon:
    """
    Basic usage:
      1. Connect to the given IP address and port:
           with DebugConnection(ip_address, port) as conn:
             ...

      2. Connect to the given IP address and port using the given server_name
         as the Server Name Indication (SNI) value:
           with DebugConnection(server_name, ip_address, port) as conn:
             ...

      3. Resolve the given server_name as an IPv4 address (unless ipv6 is True
         then it will be resolved to an IPv6 address) using the Unbound
         resolver attached to the given or current Celery worker task:
           with DebugConnection(
               server_name, port[, ipv6][, send_SNI][, task]) as conn:
             ...

      You may provide an alternate sock_setup implementation to upgrade to
      SSL/TLS after first initialising the socket connection to the correct
      state (e.g. for SMTP STARTTLS).
    """

    def __enter__(self):
        return self

    def __exit__(self, exception_type, exception_value, traceback):
        self.safe_shutdown()

    def __init__(self, **kwargs):
        self.sock = None
        self.server_name = kwargs.get('server_name')
        self.ip_address = kwargs.get('ip_address')
        self.port = kwargs.get('port')
        self.must_shutdown = kwargs.get('shutdown', False)
        self.ciphers = kwargs.get('ciphers', ALL_TLS12_AND_PRE_CIPHERS)
        self.ipv6 = kwargs.get('ipv6', False)
        self.options = kwargs.get('options')
        self.send_SNI = kwargs.get('send_SNI', True)
        self.signature_algorithms = kwargs.get('signature_algorithms', None)
        self.tries = kwargs.get('tries', MAX_TRIES)
        self.timeout = kwargs.get('timeout', DEFAULT_TIMEOUT)
        self.task = kwargs.get('task', celery_app.current_worker_task)
        self.sock_setup = kwargs.get('sock_setup', plain_sock_setup)
        self.do_handshake_on_connect = kwargs.get('do_handshake_on_connect',
            True)

        # Catch non-sensical parameter combinations and values:
        if not self.server_name:
            if self.send_SNI:
                raise ValueError('SNI requires a server name.')
            if not self.ip_address:
                raise ValueError('Either a server name or IP address is'
                    'required')
        elif self.ip_address:
            # Can raise ValueError if the string is not a valid IP address
            ip_obj = ipaddress.ip_address(self.ip_address)
            ip_obj_is_v6 = isinstance(ip_obj, ipaddress.IPv6Address)
            if ip_obj_is_v6 != self.ipv6:
                raise ValueError('Mismatched ip address type and ipv6 flag')
        elif not self.port:
            raise ValueError('A port number is required')

        # If the server_name is a DNS label (mailtest) make sure to remove the
        # trailing dot.
        self.server_name = self.server_name.rstrip(".")

        self.connect(self.do_handshake_on_connect)

    def dup(self, *args, **kwargs):
        return self.from_conn(self, *args, **kwargs)

    def sock_connect(self):
        if sslConnectLogger.isEnabledFor(logging.DEBUG):
            sslConnectLogger.debug(f"SSL connect with {type(self).__name__}"
                        f" to host '{self.server_name}'"
                        f" at IP:port {self.ip_address}:{self.port}"
                        f" using SSL version {self.version.name}"
                        f" invoked by {inspect.stack()[4].function}"
                        f" > {inspect.stack()[5].function}"
                        f" > {inspect.stack()[6].function}")
        (self.ip_address, self.sock) = sock_connect(
            self.server_name, self.ip_address, self.port, self.ipv6,
            self.task, self.timeout)

    def connect(self, do_handshake_on_connect):
        if self.sock:
            raise ValueError('Already connected')

        self.sock_setup(self)

        try:
            super().__init__(
                ssl_version=self.version,
                underlying_socket=self.sock,
                ssl_verify=SSL_VERIFY_NONE,
                ssl_verify_locations=settings.CA_CERTIFICATES,
                ignore_client_authentication_requests=True,
                signature_algorithms=self.signature_algorithms)
            if self.options:
                self.set_options(self.options)

            # TODO broken SNI-fallback
            if self.send_SNI and self.version != SSLV2:
                self.set_tlsext_host_name(self.server_name)

                # Enable the OCSP TLS extension
                # This only works if set_tlsext_host_name() is also used
                self.set_tlsext_status_ocsp()

            self._set_ciphers()

            if do_handshake_on_connect:
                self.do_handshake()
        except (socket.gaierror, socket.error, IOError, _nassl.OpenSSLError,
                ClientCertificateRequested, NotImplementedError):
            # Not able to connect to port 443
            self.safe_shutdown()
            raise ConnectionHandshakeException()
        finally:
            if self.must_shutdown:
                self.safe_shutdown()

    def safe_shutdown(self):
        """
        Shutdown TLS and socket. Ignore any exceptions.

        """
        try:
            if self.get_underlying_socket():
                self.shutdown()
            if self.sock:
                self.sock.shutdown(2)
        except (IOError, _nassl.OpenSSLError, AttributeError):
            pass
        finally:
            if self.sock:
                self.sock.close()
            self.sock = None

    def get_peer_certificate_chain(self):
        """
        Wrap nassl's method in order to catch ValueError when there is an error
        getting the peer's certificate chain.

        """
        chain = None
        try:
            chain = self.get_peer_cert_chain()
        except ValueError:
            pass
        return chain


class ModernConnection(ConnectionCommon, SslClient):
    """
    A modern OpenSSL based TLS client. Defaults to TLS 1.3 only.

    See ConnectionCommon for usage instructions.
    """
    def __init__(self, version=TLSV1_3, tls13ciphers=ALL_TLS13_CIPHERS, **kwargs):
        self.tls13ciphers = tls13ciphers
        self.version = version

        super().__init__(**kwargs)

    @staticmethod
    def from_conn(conn, *args, **kwargs):
        return ModernConnection(server_name=conn.server_name,
            ip_address=conn.ip_address, port=conn.port, ipv6=conn.ipv6,
            send_SNI=conn.send_SNI, task=conn.task, sock_setup=conn.sock_setup,
            *args, **kwargs)

    def _set_ciphers(self):
        self.set_cipher_list(self.ciphers, self.tls13ciphers)


class DebugConnection(ConnectionCommon, LegacySslClient):
    """
    A legacy OpenSSL based SSL/TLS <= TLS 1.2 client. Defaults to best possible
    protocol version.
    """
    def __init__(self, version=SSLV23, **kwargs):
        self.version = version

        super().__init__(**kwargs)

    @staticmethod
    def from_conn(conn, *args, **kwargs):
        return DebugConnection(server_name=conn.server_name,
            ip_address=conn.ip_address, port=conn.port, ipv6=conn.ipv6,
            send_SNI=conn.send_SNI, task=conn.task, sock_setup=conn.sock_setup,
            *args, **kwargs)

    def _set_ciphers(self):
        self.set_cipher_list(self.ciphers)

    def get_peer_signature_type(self):
        """
        Not implemented in OpenSSL < 1.1.1
        """
        return None


class SSLConnectionWrapper:
    """
    A NASSL based SSL connection that tries hard to connect using various
    combinations of protocol settings and  with an http.client.HTTPConnection like
    interface. Makes a TLS connection using ModernConnection for TLS 1.3,
    otherwise connecting with the highest possible SSL/TLS version supported
    by DebugConnection for target servers that do not support newer protocols
    and ciphers.

    This class should be used instead of native Python SSL/TLS connectivity
    because the native functionality does not support legacy protocols,
    protocol features and ciphers.
    """
    def __init__(self, conn=None, **kwargs):
        if conn:
            # Use an existing connection
            self.host = conn.server_name
            self.conn = conn
        else:
            try:
                # First see if the server supports TLS 1.3
                # Do not use ModernConnection for other protocol versions as it
                # lacks support for verifying TLS compression, insecure
                # renegotiation and client renegotiation.
                self.conn = ModernConnection(version=TLSV1_3, **kwargs)
            except ConnectionHandshakeException:
                try:
                    # No TLS 1.3? Try TLS 1.2, TLS 1.1, TLS 1.0 and SSL 3.0.
                    # We don't have support for SSL 2.0.
                    self.conn = DebugConnection(version=SSLV23, **kwargs)
                except ConnectionHandshakeException:
                    # Now, try TLS 1.2 again but this time with
                    # ModernConnection because while it lacks some features it
                    # also supports some ciphers that DebugConnection does not,
                    # better to verify what we can than fail to connect at all.
                    # Ciphers known to be unsupported by DebugConnection but
                    # supported by ModernConnection include:
                    #   - AES128-CCM
                    #   - DHE-RSA-CHACHA20-POLY1305
                    #   - ECDHE-RSA-CHACHA20-POLY1305
                    #   - ECDHE-ECDSA-CHACHA20-POLY1305
                    self.conn = ModernConnection(version=TLSV1_2, **kwargs)

            # For similarity/compatibility with http.client.HTTP(S)Connection:
            self.host = self.conn.server_name
            self.port = self.conn.port

    def __enter__(self):
        return self.conn.__enter__()

    def __exit__(self, exception_type, exception_value, traceback):
        return self.conn.__exit__(exception_type, exception_value, traceback)


class HTTPSConnection(SSLConnectionWrapper):
    """
    A NASSL based HTTPS connection with an http.client.HTTPConnection like
    interface.

    HTTP requests are simple HTTP/1.1 one-shot (connection: close) requests.
    HTTP responses are truncated at a maximum of 8192 bytes. This class is NOT
    intended to be a general purpose rich HTTP client.
    """
    def __init__(self, host=None, port=None,
            timeout=socket._GLOBAL_DEFAULT_TIMEOUT, socket_af=socket.AF_INET,
            task=None, ip_address=None, conn=None, **kwargs):
        if conn:
            super().__init__(conn=conn)
        else:
            ipv6 = True if socket_af is socket.AF_INET6 else False
            port = 443 if not port else port
            super().__init__(
                server_name=host, ip_address=ip_address, port=port, ipv6=ipv6,
                tries=1, timeout=timeout, task=task, **kwargs)

    @classmethod
    def fromconn(cls, conn):
        return cls(conn=conn)

    def write(self, data):
        if self.conn.is_handshake_completed():
            self.conn.write(data)
        elif self.conn.get_ssl_version() == TLSV1_3:
            self.conn.write_early_data(data)

    def writestr(self, str, encoding='ascii'):
        self.write(str.encode(encoding))

    def putrequest(self, method, path, skip_accept_encoding=True):
        self.writestr('{} {} HTTP/1.1\r\n'.format(method, path))
        self.putheader('Host', self.host)
        self.putheader('Connection', 'close')

    def putheader(self, name, value):
        self.writestr('{}: {}\r\n'.format(name, value))

    def endheaders(self):
        self.writestr('\r\n')

    def getresponse(self):
        # Based on: https://stackoverflow.com/a/47687312
        class BytesIOSocket:
            def __init__(self, content):
                self.handle = BytesIO(content)

            def makefile(self, mode):
                return self.handle

        class AutoUpdatingHTTPResponse(http.client.HTTPResponse):
            def __init__(self, conn):
                self.conn = conn
                self.bytesio = BytesIOSocket(self._fetch_headers())
                super().__init__(self.bytesio)

            def _fetch_headers(self):
                # read all HTTP headers (i.e. until \r\n\r\n or EOF)
                data = bytearray()
                while b'\r\n\r\n' not in data:
                    data.extend(self.conn.read(1024))
                return data

            def _update(self, amt):
                # save the current position in the underlying buffer, hope that
                # no other code accesses the buffer while we are working with
                # it.
                pos = self.bytesio.handle.tell()

                # move the read/write cursor in the underlying buffer to the end
                # so that we append to the existing data.
                self.bytesio.handle.seek(0, 2)

                # read and decrypt upto the number of requested bytes from the
                # network and write them to the underlying buffer.
                chunk_size = amt if amt and amt < 8192 else 8192
                try:
                    while not amt or (self.bytesio.handle.tell() - pos) < amt:
                        self.bytesio.handle.write(
                            self.conn.read(chunk_size))
                except IOError:
                    pass

                # reset the read/write cursor to the original position
                self.bytesio.handle.seek(pos, 0)

            def read(self, amt=None):
                # fetch additional response bytes on demand
                self._update(amt)

                # delegate actual response byte processing to the base class
                return super().read(amt)

        def response_from_bytes(data):
            response = AutoUpdatingHTTPResponse(self.conn)
            response.begin()
            return response

        return response_from_bytes(None)

    def close(self):
        self.conn.safe_shutdown()


class HTTPConnection(http.client.HTTPConnection):
    def __init__(
            self, host, port=None, timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
            source_address=None, socket_af=socket.AF_INET, task=None,
            ip_address=None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.socket_af = socket_af
        self.task = task
        self.ip_address = ip_address

        http.client.HTTPConnection.__init__(
            self, host, port, timeout, source_address)

    def connect(self):
        ipv6 = True if self.socket_af is socket.AF_INET6 else False
        (self.ip_address, self.sock) = sock_connect(self.host, self.ip_address,
            self.port, ipv6, self.task, self.timeout)


# TODO: document and/or clean up the possible set of raised exceptions
# TODO: remove task parameter and instead use celery_app.current_worker_task?
def http_fetch(
        host, af=socket.AF_INET, path="/", port=80, http_method="GET",
        task=None, depth=0, ip_address=None, put_headers=[], ret_headers=None,
        needed_headers=[], ret_visited_hosts=None,
        keep_conn_open=False):
    if path == "":
        path = "/"

    tries_left = MAX_TRIES
    timeout = 10
    while tries_left > 0:
        try:
            conn = None
            if port == 443:
                conn = HTTPSConnection(
                    host=host, ip_address=ip_address, port=port, socket_af=af,
                    task=task, timeout=timeout)
            else:
                conn = HTTPConnection(
                    host=host, ip_address=ip_address, port=port, socket_af=af,
                    task=task, timeout=timeout)
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
        except (socket.error, ConnectionSocketException):
            try:
                if conn:
                    conn.close()
            except (socket.error, http.client.HTTPException):
                pass
            tries_left -= 1
            if tries_left <= 0:
                raise
            time.sleep(1)
        # If we got another exception just raise it.
        except (http.client.HTTPException, ConnectionHandshakeException):
            try:
                if conn:
                    conn.close()
            except (socket.error, http.client.HTTPException):
                pass
            raise

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


# Simplified use of http_fetch that also downloads and decodes the response
# body. Similar to calling requests.get(). Passes the current Celery task (if
# any) for name resolution so that the caller doesn't have to pass the task
# around just to get it to this point, the caller shouldn't need to know about
# celery tasks just to be able to do a HTTP GET...
# TODO: document the possible set of raised exceptions
# TODO: properly extract host from netloc.
# TODO: don't discard the remainder of the "path" (params, query, fragment)
def http_get(url):
    scheme, netloc, path, *unused = urlparse(url)
    port = 443 if scheme == 'https' else 80
    conn, r, *unused = http_fetch(host=netloc, path=path,
        port=port, keep_conn_open=True)
    rr = namedtuple('Response', ['status_code', 'text'])
    rr.status_code = r.status
    if r.status == 200:
        ct_header = r.getheader('Content-Type', None)
        if ct_header:
            encoding = parse_header(ct_header)[1]['charset']
        else:
            encoding = 'utf-8'
        rr.text = r.read().decode(encoding)
    conn.close()
    return rr
