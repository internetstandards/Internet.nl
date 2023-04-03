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
from checks.tasks.tls_connection_exceptions import NoIpError
from internetnl import log

# Disable HTTPS warnings as we intentionally disable HTTPS verification
urllib3.disable_warnings()


def http_get(
    url: str, headers: Optional[Dict] = None, session: Optional[requests.Session] = None, *args, **kwargs
) -> requests.Response:
    """
    Perform a HTTP GET request using the stored session
    """
    # TODO: auto-retry
    start_time = timer()

    if not headers:
        headers = {}
    headers["User-Agent"] = "internetnl/1.0"
    if not session:
        session = requests.session()

    response = session.get(url, headers=headers, stream=True, *args, **kwargs)
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
    path = path.lstrip("/")
    if not headers:
        headers = {}

    session = requests.session()
    if https:
        session.mount(f"https://{hostname}", ForcedIPHTTPSAdapter(dest_ip=ip))
        url = f"https://{hostname}:{port}/{path}"
    else:
        if ":" in ip:
            ip = f"[{ip}]"
        url = f"http://{ip}:{port}/{path}"
    headers["Host"] = hostname
    return http_get(url, verify=False, headers=headers, session=session, *args, **kwargs)


def http_get_af(
    hostname: str, port: int, af: socket.AddressFamily, task: Optional[SetupUnboundContext] = None, *args, **kwargs
) -> requests.Response:
    rr_type = unbound.RR_TYPE_AAAA if af == socket.AF_INET6 else unbound.RR_TYPE_A
    # cb_data = ub_resolve_with_timeout(host, rr_type, unbound.RR_CLASS_IN, timeout)
    # ips = [socket.inet_ntop(af, rr) for rr in cb_data["data"].data]
    ips = task.resolve(hostname, rr_type)
    exc = NoIpError(f"Unable to resolve {rr_type} record for host '{hostname}'")
    for ip in ips:
        try:
            return http_get_ip(hostname, ip, port, *args, **kwargs)
        except requests.RequestException as request_exception:
            exc = request_exception
    raise exc
