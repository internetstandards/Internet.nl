import http.client
import inspect
import ipaddress
import logging
import socket
import time
from enum import Enum
from io import BytesIO
from urllib.parse import urlparse

from celery.utils.log import get_task_logger
from django.conf import settings
from nassl import _nassl
from nassl.legacy_ssl_client import LegacySslClient
from nassl.ssl_client import ClientCertificateRequested, OpenSslVerifyEnum, OpenSslVersionEnum, SslClient

from checks.tasks import unbound
from checks.tasks.tls_connection_exceptions import ConnectionHandshakeException, ConnectionSocketException, NoIpError
from interface.views.shared import ub_resolve_with_timeout
from internetnl import celery_app

# Use a dedicated logger as this logging can be very verbose
sslConnectLogger = get_task_logger("internetnl.ssl.connect")

HTTPS_READ_CHUNK_SIZE = 8192

SSLV23 = OpenSslVersionEnum.SSLV23
SSLV2 = OpenSslVersionEnum.SSLV2
SSLV3 = OpenSslVersionEnum.SSLV3
TLSV1 = OpenSslVersionEnum.TLSV1
TLSV1_1 = OpenSslVersionEnum.TLSV1_1
TLSV1_2 = OpenSslVersionEnum.TLSV1_2
TLSV1_3 = OpenSslVersionEnum.TLSV1_3


SSL_VERIFY_NONE = OpenSslVerifyEnum.NONE


# Increase http.client's _MAXHEADERS from 100 to 200.
# We had problems with a site that uses too many 'Link' headers.
http.client._MAXHEADERS = 200

# Maximum number of tries on failure to establish a connection.
# Useful with servers slow to establish first connection. (slow stateful
# firewalls?, slow spawning of threads/processes to handle the request?).
MAX_TRIES = 2
MAX_REDIRECT_DEPTH = 8
DEFAULT_TIMEOUT = 10


def sock_connect(host, ip, port, ipv6=False, task=None, timeout=DEFAULT_TIMEOUT):
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
            cb_data = ub_resolve_with_timeout(host, rr_type, unbound.RR_CLASS_IN, timeout)
            af = socket.AF_INET6 if ipv6 else socket.AF_INET
            ips = [socket.inet_ntop(af, rr) for rr in cb_data["data"].data]
        if not ips:
            raise NoIpError(f"Unable to resolve {rr_type} record for host '{host}'")

    # Return the connection details for the first IP address that we can
    # successfully connect to.
    af = socket.AF_INET6 if ipv6 else socket.AF_INET
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
    raise err


# TODO: factor out TLS test specific functionality (used in tls.py) from basic
# connectivity (used here by http_fetch and also by tls.py).


# Almost identical to HTTPConnection::_create_conn()
def plain_sock_setup(conn):
    conn.sock = None

    tries_left = conn.tries
    while tries_left > 0:
        try:
            conn.sock_connect()
            break
        except (socket.gaierror, OSError, ConnectionRefusedError):
            conn.safe_shutdown()
            tries_left -= 1
            if tries_left <= 0:
                raise ConnectionSocketException()
            time.sleep(1)
        except NoIpError:
            raise ConnectionSocketException()


# TDDO: use the 'overload' module to cleanup the init argument passing and make
# it clearer what is happening?
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
        self.server_name = kwargs.get("server_name")
        self.ip_address = kwargs.get("ip_address")
        self.port = kwargs.get("port")
        self.must_shutdown = kwargs.get("shutdown", False)
        self.ipv6 = kwargs.get("ipv6", False)
        self.options = kwargs.get("options")
        self.send_SNI = kwargs.get("send_SNI", True)
        self.signature_algorithms = kwargs.get("signature_algorithms", None)
        self.tries = kwargs.get("tries", MAX_TRIES)
        self.timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        self.task = kwargs.get("task", celery_app.current_worker_task)
        self.sock_setup = kwargs.get("sock_setup", plain_sock_setup)
        self.do_handshake_on_connect = kwargs.get("do_handshake_on_connect", True)
        self.cipher_list_action = kwargs.get("cipher_list_action", CipherListAction.REPLACE)

        # Catch non-sensical parameter combinations and values:
        if not self.server_name:
            if self.send_SNI:
                raise ValueError("SNI requires a server name.")
            if not self.ip_address:
                raise ValueError("Either a server name or IP address is required")
        elif self.ip_address:
            # Can raise ValueError if the string is not a valid IP address
            ip_obj = ipaddress.ip_address(self.ip_address)
            ip_obj_is_v6 = isinstance(ip_obj, ipaddress.IPv6Address)
            if ip_obj_is_v6 != self.ipv6:
                raise ValueError("Mismatched ip address type and ipv6 flag")
        elif not self.port:
            raise ValueError("A port number is required")

        # If the server_name is a DNS label (mailtest) make sure to remove the
        # trailing dot.
        self.server_name = self.server_name.rstrip(".")

        self._handle_cipher_list_action(self.ciphers, self.cipher_list_action)

        self.connect(self.do_handshake_on_connect)

    def _handle_cipher_list_action(self, ciphers, cipher_list_action):
        if cipher_list_action == CipherListAction.REPLACE:
            self.ciphers = ciphers
        elif cipher_list_action == CipherListAction.APPEND:
            self.ciphers = f"{self.ALL_CIPHERS}:{ciphers}"
        elif cipher_list_action == CipherListAction.PREPEND:
            self.ciphers = f"{ciphers}:{self.ALL_CIPHERS}"
        else:
            raise ValueError()

    def dup(self, *args, **kwargs):
        return self.from_conn(self, *args, **kwargs)

    def sock_connect(self, any_af=False):
        try:
            if sslConnectLogger.isEnabledFor(logging.DEBUG):
                sslConnectLogger.debug(
                    f"SSL connect with {type(self).__name__}"
                    f" to host '{self.server_name}'"
                    f" at IP:port {self.ip_address}:{self.port}"
                    f" using SSL version {self.version.name}"
                    f" invoked by {inspect.stack()[4].function}"
                    f" > {inspect.stack()[5].function}"
                    f" > {inspect.stack()[6].function}"
                )
            (self.ip_address, self.sock) = sock_connect(
                self.server_name, self.ip_address, self.port, self.ipv6, self.task, self.timeout
            )
        except (OSError, NoIpError):
            if not (any_af or self.ip_address):
                raise
            self.ipv6 = not self.ipv6
            (self.ip_address, self.sock) = sock_connect(
                self.server_name, self.ip_address, self.port, self.ipv6, self.task, self.timeout
            )

    def connect(self, do_handshake_on_connect):
        if self.sock:
            raise ValueError("Already connected")

        self.sock_setup(self)

        try:
            super().__init__(
                ssl_version=self.version,
                underlying_socket=self.sock,
                ssl_verify=SSL_VERIFY_NONE,
                ssl_verify_locations=settings.CA_CERTIFICATES,
                ignore_client_authentication_requests=True,
                signature_algorithms=self.signature_algorithms,
            )
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
        except (socket.gaierror, OSError, _nassl.OpenSSLError, ClientCertificateRequested, NotImplementedError):
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
        except (OSError, _nassl.OpenSSLError, AttributeError):
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


class CipherListAction(Enum):
    REPLACE = 0
    PREPEND = 1
    APPEND = 2


class ModernConnection(ConnectionCommon, SslClient):
    """
    A modern OpenSSL based TLS client. Defaults to TLS 1.3 only.

    See ConnectionCommon for usage instructions.

    """

    ALL_CIPHERS = "ALL:COMPLEMENTOFALL@SECLEVEL=0"

    ALL_TLS13_CIPHERS = None

    def __init__(self, version=TLSV1_3, ciphers=ALL_CIPHERS, tls13ciphers=None, **kwargs):
        self.init_all_tls13_ciphers()
        self.ciphers = ciphers
        self.tls13ciphers = tls13ciphers if tls13ciphers else self.ALL_TLS13_CIPHERS
        self.version = version
        super().__init__(**kwargs)

    @classmethod
    def init_all_tls13_ciphers(cls):
        """
        Lazily compute the TLS 1.3 all ciphers string in order to avoid a
        circular dependency on cipher_info.

        """
        if not cls.ALL_TLS13_CIPHERS:
            from checks.tasks.cipher_info import cipher_infos

            # There is no 'ALL' or other meta cipher suite names when building
            # a TLS 1.3 cipher suite list for OpenSSL, instead one must
            # construct it using only the colon ':' character to separate TLS
            # 1.3 cipher names. At the time of writing our underlying OpenSSL
            # 1.1.1 library build doesn't support all of the TLS 1.3 ciphers
            # AND doesn't ignore unknown ciphers either. So, construct a list
            # of just those that we _do_ support.
            cls.ALL_TLS13_CIPHERS = ":".join(
                x.name for x in filter(lambda x: x.tls_version == "TLSv1.3", cipher_infos.values())
            )
        return cls.ALL_TLS13_CIPHERS

    @staticmethod
    def from_conn(conn, *args, **kwargs):
        return ModernConnection(
            server_name=conn.server_name,
            ip_address=conn.ip_address,
            port=conn.port,
            ipv6=conn.ipv6,
            send_SNI=conn.send_SNI,
            task=conn.task,
            sock_setup=conn.sock_setup,
            timeout=conn.timeout,
            *args,
            **kwargs,
        )

    def _set_ciphers(self):
        self.set_cipher_list(self.ciphers, self.tls13ciphers)


class DebugConnection(ConnectionCommon, LegacySslClient):
    """
    A legacy OpenSSL based SSL/TLS <= TLS 1.2 client. Defaults to best possible
    protocol version.

    """

    ALL_CIPHERS = "ALL:COMPLEMENTOFALL"

    def __init__(self, version=SSLV23, ciphers=ALL_CIPHERS, **kwargs):
        self.ciphers = ciphers
        self.version = version
        super().__init__(**kwargs)

    @staticmethod
    def from_conn(conn, *args, **kwargs):
        return DebugConnection(
            server_name=conn.server_name,
            ip_address=conn.ip_address,
            port=conn.port,
            ipv6=conn.ipv6,
            send_SNI=conn.send_SNI,
            task=conn.task,
            sock_setup=conn.sock_setup,
            timeout=conn.timeout,
            *args,
            **kwargs,
        )

    def _set_ciphers(self):
        self.set_cipher_list(self.ciphers)


class SSLConnectionWrapper:
    """
    A NASSL based SSL connection that tries hard to connect using various
    combinations of protocol settings and  with an http.client.HTTPConnection
    like interface. Makes a TLS connection using ModernConnection for TLS 1.3,
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
            # First see if the server supports TLS 1.3
            # Do not use ModernConnection for other protocol versions as it
            # lacks support for verifying TLS compression, insecure
            # renegotiation and client renegotiation.
            # Note: TLS related tests may rely on the information if
            # TLS 1.3 connection was explicitly possible or not.
            #
            # No TLS 1.3? Try the lesser versions. For SSLV2 we need to
            # explicitly set it.
            #
            # Now, try ModernConnection again because, while it lacks
            # some features, it
            # also supports some ciphers that DebugConnection does not,
            # better to verify what we can than fail to connect at all.
            # Ciphers known to be unsupported by DebugConnection but
            # supported by ModernConnection include:
            #   - AES128-CCM
            #   - DHE-RSA-CHACHA20-POLY1305
            #   - ECDHE-RSA-CHACHA20-POLY1305
            #   - ECDHE-ECDSA-CHACHA20-POLY1305
            connection_attempts = [
                (ModernConnection, TLSV1_3),
                (DebugConnection, SSLV23),
                (DebugConnection, SSLV2),
                (ModernConnection, SSLV23),
            ]
            fails = 0
            for current_conn, current_version in connection_attempts:
                try:
                    self.conn = current_conn(version=current_version, **kwargs)
                    break
                except ConnectionHandshakeException:
                    fails += 1
                    if fails >= len(connection_attempts):
                        raise

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
    This class is NOT intended to be a general purpose rich HTTP client.

    """

    def __init__(
        self,
        host=None,
        port=None,
        timeout=DEFAULT_TIMEOUT,
        socket_af=socket.AF_INET,
        task=None,
        ip_address=None,
        conn=None,
        **kwargs,
    ):
        if conn:
            super().__init__(conn=conn)
        else:
            ipv6 = True if socket_af is socket.AF_INET6 else False
            port = 443 if not port else port
            super().__init__(
                server_name=host,
                ip_address=ip_address,
                port=port,
                ipv6=ipv6,
                tries=1,
                timeout=timeout,
                task=task,
                **kwargs,
            )

    @classmethod
    def fromconn(cls, conn):
        return cls(conn=conn)

    def write(self, data):
        if self.conn.is_handshake_completed():
            self.conn.write(data)
        elif self.conn.get_ssl_version() == TLSV1_3:
            self.conn.write_early_data(data)

    def writestr(self, str, encoding="ascii"):
        self.write(str.encode(encoding))

    def putrequest(self, method, path, skip_accept_encoding=True):
        self.writestr(f"{method} {path} HTTP/1.1\r\n")
        self.putheader("Host", self.host)
        self.putheader("Connection", "close")

    def putheader(self, name, value):
        self.writestr(f"{name}: {value}\r\n")

    def endheaders(self):
        self.writestr("\r\n")

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
                while b"\r\n\r\n" not in data:
                    data.extend(self.conn.read(1024))
                return data

            def _update(self, amt):
                # save the current position in the underlying buffer, hope that
                # no other code accesses the buffer while we are working with
                # it.
                pos = self.bytesio.handle.tell()

                # move the read/write cursor in the underlying buffer to the
                # end so that we append to the existing data.
                self.bytesio.handle.seek(0, 2)

                # read and decrypt upto the number of requested bytes from the
                # network and write them to the underlying buffer.
                chunk_size = amt if amt and amt < HTTPS_READ_CHUNK_SIZE else HTTPS_READ_CHUNK_SIZE
                try:
                    while not amt or (self.bytesio.handle.tell() - pos) < amt:
                        self.bytesio.handle.write(self.conn.read(chunk_size))
                except OSError:
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
        self,
        host,
        port=None,
        timeout=DEFAULT_TIMEOUT,
        source_address=None,
        socket_af=socket.AF_INET,
        task=None,
        ip_address=None,
    ):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.socket_af = socket_af
        self.task = task
        self.ip_address = ip_address

        http.client.HTTPConnection.__init__(self, host, port, timeout, source_address)

    def connect(self):
        ipv6 = True if self.socket_af is socket.AF_INET6 else False
        (self.ip_address, self.sock) = sock_connect(
            self.host, self.ip_address, self.port, ipv6, self.task, self.timeout
        )


# TODO: document and/or clean up the possible set of raised exceptions
# TODO: remove task parameter and instead use celery_app.current_worker_task?
def http_fetch(
    host,
    af=socket.AF_INET,
    path="/",
    port=80,
    http_method="GET",
    task=None,
    depth=0,
    ip_address=None,
    put_headers=[],
    ret_headers=None,
    needed_headers=[],
    ret_visited_hosts=None,
    keep_conn_open=False,
    needed_headers_follow_redirect=False,
):
    if path == "":
        path = "/"

    tries_left = MAX_TRIES
    timeout = 10
    while tries_left > 0:
        try:
            conn = None
            if port == 443:
                conn = HTTPSConnection(
                    host=host,
                    ip_address=ip_address,
                    port=port,
                    socket_af=af,
                    task=task,
                    timeout=timeout,
                )
            else:
                conn = HTTPConnection(
                    host=host, ip_address=ip_address, port=port, socket_af=af, task=task, timeout=timeout
                )
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
        except (OSError, ConnectionSocketException):
            try:
                if conn:
                    conn.close()
            except (OSError, http.client.HTTPException):
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
            except (OSError, http.client.HTTPException):
                pass
            raise
        except _nassl.OpenSSLError:
            try:
                if conn:
                    conn.close()
            except (OSError, http.client.HTTPException):
                pass
            raise ConnectionHandshakeException

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
    if 300 <= res.status < 400 and depth < MAX_REDIRECT_DEPTH and res.getheader("location"):
        u = urlparse(res.getheader("location"))
        if u.scheme == "https":
            port = 443
        if u.netloc != "":
            host = u.netloc
        host = host.split(":")[0]
        path = u.path
        if not path.startswith("/"):
            path = "/" + path
        # If the connection was not closed earlier, close it.
        if keep_conn_open:
            conn.close()
        depth += 1
        return http_fetch(
            host,
            af=af,
            path=path,
            port=port,
            http_method=http_method,
            task=task,
            depth=depth,
            ret_headers=ret_headers,
            ret_visited_hosts=ret_visited_hosts,
            keep_conn_open=keep_conn_open,
            # By default, needed_headers are returned based on the first response -
            # this follow_redirect flag returns them from the last response instead
            # for security.txt. Also see #378
            needed_headers=needed_headers if needed_headers_follow_redirect else [],
            needed_headers_follow_redirect=needed_headers_follow_redirect,
        )

    return conn, res, ret_headers, ret_visited_hosts
