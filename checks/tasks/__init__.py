# Copyright: 2022, ECP, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
import os
from typing import Dict, Optional

import requests
import socket
import time

import urllib3
from celery import Task
from celery.exceptions import SoftTimeLimitExceeded
from django.conf import settings

import unbound
from forcediphttpsadapter.adapters import ForcedIPHTTPSAdapter

from checks.tasks.tls_connection_exceptions import NoIpError
from internetnl import log
from timeit import default_timer as timer

# Disable HTTPS warnings.
# TODO: is this the best place for this call?
urllib3.disable_warnings()


class SetupUnboundContext(Task):
    """
    Abstract class to initiate unbound context. Use as celery baseclass.

    """

    abstract = True
    _ub_ctx = None

    @property
    def ub_ctx(self):
        if self._ub_ctx is None:
            self._ub_ctx = unbound.ub_ctx()
            if hasattr(settings, "ENABLE_INTEGRATION_TEST") and settings.ENABLE_INTEGRATION_TEST:
                self._ub_ctx.debuglevel(2)
                self._ub_ctx.config(settings.IT_UNBOUND_CONFIG_PATH)
                self._ub_ctx.set_fwd(settings.IT_UNBOUND_FORWARD_IP)
            else:
                self._ub_ctx.add_ta_file(os.path.join(os.getcwd(), settings.DNS_ROOT_KEY))
            self._ub_ctx.set_option("cache-max-ttl:", str(settings.CACHE_TTL * 0.9))
            # Some (unknown) tests probably depend on consistent ordering in unbound responses
            # https://github.com/internetstandards/Internet.nl/pull/613#discussion_r892196819
            self._ub_ctx.set_option("rrset-roundrobin:", "no")
            self._ub_ctx.set_option("cache-max-ttl:", str(settings.CACHE_TTL * 0.9))
            # XXX: Remove for now; inconsistency with applying settings on celery.
            # YYY: Removal caused infinite waiting on pipe to unbound. Added again.
            self._ub_ctx.set_async(True)
            if settings.ENABLE_BATCH and settings.CENTRAL_UNBOUND:
                self._ub_ctx.set_fwd(f"{settings.CENTRAL_UNBOUND}")

        return self._ub_ctx

    def async_resolv(self, qname, qtype, callback=None, cb_data=None):
        if not callback:
            callback = self.callback

        if not cb_data:
            cb_data = dict(done=False)
        else:
            # Make sure the provided cb_data has the required value.
            cb_data["done"] = False

        try:
            log.debug("Attempting resolving of qname: %s" % qname)
            retval, async_id = self.ub_ctx.resolve_async(qname, cb_data, callback, qtype, unbound.RR_CLASS_IN)
            while retval == 0 and not cb_data["done"]:
                time.sleep(0.1)
                retval = self.ub_ctx.process()

        except SoftTimeLimitExceeded as e:
            log.debug("Soft time limit exceeded.")
            log.debug("Failed resolving of qname: %s" % qname)
            if async_id:
                self.ub_ctx.cancel(async_id)
            raise e

        log.debug(f"Got data: {cb_data}, retval: {retval}.")
        return cb_data

    def resolve(self, qname, qtype):
        resp = self.async_resolv(qname, qtype)
        if "data" in resp:
            if qtype == unbound.RR_TYPE_AAAA:
                return [socket.inet_ntop(socket.AF_INET6, rr) for rr in resp["data"].data]
            elif qtype == unbound.RR_TYPE_A:
                return [socket.inet_ntop(socket.AF_INET, rr) for rr in resp["data"].data]
            elif qtype == unbound.RR_TYPE_MX:
                return resp["data"].as_mx_list()
            elif qtype == unbound.RR_TYPE_TXT:
                return [unbound.ub_data.dname2str(d) for d in resp["data"].data]
            elif qtype == 52:  # unbound.RR_TYPE_TLSA
                # RDATA is split with ';' by pyunbound.
                dane_data = str(resp["data"]).split(";")
                dane_records = []
                for record in dane_data:
                    chars = record.split()
                    try:
                        cert_usage = int(chars[0], 16)
                        selector = int(chars[1], 16)
                        match = int(chars[2], 16)
                        data = "".join(chars[3:])
                        dane_records.append((cert_usage, selector, match, data))
                    except (ValueError, IndexError):
                        # Invalid record; ignore.
                        pass
                resp["data"] = dane_records
                return resp
            else:
                return resp["data"].as_domain_list()
        return {}

    def callback(self, data, status, result):
        if status == 0:
            data["secure"] = result.secure
            data["bogus"] = result.bogus
            data["nxdomain"] = result.nxdomain
            if result.havedata:
                data["data"] = result.data
                data["rcode"] = result.rcode
        data["done"] = True

    def http_get(
        self, url: str, headers: Optional[Dict] = None, session: Optional[requests.Session] = None, *args, **kwargs
    ) -> requests.Response:
        """
        Perform a HTTP GET request using the stored session
        """
        # TODO: auto-retry
        # TODO: make this this runnable from outside a task
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
        self,
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
        return self.http_get(url, verify=False, headers=headers, session=session, *args, **kwargs)

    def http_get_af(self, hostname: str, port: int, af: socket.AddressFamily, *args, **kwargs) -> requests.Response:
        rr_type = unbound.RR_TYPE_AAAA if af == socket.AF_INET6 else unbound.RR_TYPE_A
        # cb_data = ub_resolve_with_timeout(host, rr_type, unbound.RR_CLASS_IN, timeout)
        # ips = [socket.inet_ntop(af, rr) for rr in cb_data["data"].data]
        ips = self.resolve(hostname, rr_type)
        exc = NoIpError(f"Unable to resolve {rr_type} record for host '{hostname}'")
        for ip in ips:
            try:
                return self.http_get_ip(hostname, ip, port, *args, **kwargs)
            except requests.RequestException as request_exception:
                exc = request_exception
        raise exc
