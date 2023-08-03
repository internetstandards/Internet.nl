# Copyright: 2022, ECP, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
import socket
from timeit import default_timer as timer
from typing import Optional, Dict

import requests
import unbound
import urllib3
from forcediphttpsadapter.adapters import ForcedIPHTTPSAdapter

from checks.tasks import SetupUnboundContext
from checks.tasks.tls_connection import DEFAULT_TIMEOUT
from checks.tasks.tls_connection_exceptions import NoIpError
from interface.views.shared import ub_resolve_with_timeout
from internetnl import log

# Disable HTTPS warnings as we intentionally disable HTTPS verification
urllib3.disable_warnings()


def _do_request(args, headers, kwargs, session, url):
    """
    This small wrapper helps with handling of redirects.
    As we often connect on an explicit IP, we also set an explicit Host header
    as it can't be inferred from the URL. However, this breaks redirect following,
    causing a redirect loop (#1033). This wrapper makes sure to remove it before
    following the redirect chain, then ensures response.history is complete.
    """
    user_allow_redirects = kwargs.pop("allow_redirects", True)
    response = session.get(url, headers=headers, stream=True, allow_redirects=False, *args, **kwargs)
    if response.next and user_allow_redirects:
        headers.pop("Host", None)
        initial_response = response
        response = session.get(
            initial_response.next.url, headers=headers, stream=True, allow_redirects=True, *args, **kwargs
        )
        response.history.insert(0, initial_response)

    return response


def http_get(
    url: str, headers: Optional[Dict] = None, session: Optional[requests.Session] = None, *args, **kwargs
) -> requests.Response:
    """
    Perform a standard HTTP GET request. If session is given, it is used.
    Other (kw)args are passed to requests.get.
    """
    start_time = timer()

    if not headers:
        headers = {}
    headers["User-Agent"] = "internetnl/1.0"
    if not session:
        session = requests.session()

    try:
        response = _do_request(args, headers, kwargs, session, url)
    except requests.RequestException:
        # Retry, once, then log and raise the exception
        try:
            response = _do_request(args, headers, kwargs, session, url)
        except requests.RequestException as exc:
            log.debug(f"HTTP request raised exception: {url} (headers: {headers}): {exc}", exc_info=exc)
            raise exc

    log.debug(f"HTTP request completed in {timer()-start_time:.06f}s: {url} (headers: {headers})")
    return response


def http_get_ip(
    hostname: str,
    ip: str,
    port: int,
    path: str = "/",
    https: bool = True,
    headers: Optional[Dict] = None,
    *args,
    **kwargs,
) -> requests.Response:
    """
    Perform an HTTP GET with the given parameters, while forcing the destination IP
    to a particular IP that may not match the hostname.
    TLS certificate verification is always disabled.
    Other (kw)args are passed to requests.get.
    """
    path = path.lstrip("/")
    if not headers:
        headers = {}

    session = requests.session()
    session.mount(f"https://{hostname}", ForcedIPHTTPSAdapter(dest_ip=ip))
    if https:
        port_suffix = "" if port == 443 else f":{port}"
        url = f"https://{hostname}{port_suffix}/{path}"
    else:
        if ":" in ip:
            ip = f"[{ip}]"
        port_suffix = "" if port == 80 else f":{port}"
        url = f"http://{ip}{port_suffix}/{path}"
    headers["Host"] = hostname
    return http_get(url, verify=False, headers=headers, session=session, *args, **kwargs)


def http_get_af(
    hostname: str, port: int, af: socket.AddressFamily, task: Optional[SetupUnboundContext] = None, *args, **kwargs
) -> requests.Response:
    """
    Perform an HTTP GET request to the given hostname/port, restricting to a certain address family.
    Other (kw)args are passed to requests.get.
    """
    rr_type = unbound.RR_TYPE_AAAA if af == socket.AF_INET6 else unbound.RR_TYPE_A
    if task:
        ips = task.resolve(hostname, rr_type)
    else:
        cb_data = ub_resolve_with_timeout(hostname, rr_type, unbound.RR_CLASS_IN, DEFAULT_TIMEOUT)
        ips = [socket.inet_ntop(af, rr) for rr in cb_data["data"].data]
    exc = NoIpError(f"Unable to resolve {rr_type} record for host '{hostname}'")
    for ip in ips:
        try:
            return http_get_ip(hostname, ip, port, *args, **kwargs)
        except requests.RequestException as request_exception:
            exc = request_exception
    raise exc
