# Copyright: 2022, ECP, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
import random
import re
from datetime import datetime
from urllib.parse import urlparse

import dns
import idna
import yaml
from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import DisallowedRedirect
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils.translation import gettext as _
from dns.rdatatype import RdataType
from dns.resolver import NXDOMAIN, NoAnswer, LifetimeTimeout, NoNameservers
from dns.exception import Timeout

from checks.resolver import dns_resolve, dns_resolve_soa
from checks.tasks.dispatcher import ProbeTaskResult
from internetnl import log


# See: https://stackoverflow.com/a/53875771 for a good summary of the various
# RFCs and other rulings that combine to define what is a valid domain name.
# Of particular note are xn-- which is used for internationalized TLDs, and
# the rejection of digits in the TLD if not xn--. Digits in the last label
# were legal under the original RFC-1035 but not according to the "ICANN
# Application Guidebook for new TLDs (June 2012)" which stated that "The
# ASCII label must consist entirely of letters (alphabetic characters a-z)".
regex_dname = r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+" "([a-zA-Z]{2,63}|xn--[a-zA-Z0-9]+)$"


def validate_dname(dname):
    """
    Validates a domain name and return canonical version.

    If *dname* does not contain a valid domain name, returns `None`.

    """
    try:
        urlp = urlparse(dname)
        if urlp.netloc != "":
            dname = urlp.netloc
        elif urlp.path != "":
            dname = urlp.path

        # Convert to punnycode
        dname = idna.encode(dname).decode("ascii")

        if re.match(regex_dname, dname):
            log.debug(f"Domain {dname} is valid.")
            return dname
        else:
            log.debug(f"Domain {dname} is not valid.")
            return None
    except (UnicodeError, ValueError, idna.IDNAError):
        log.debug(f"Domain {dname} is not valid and caused an exception.")
        return None


def proberesults(request, probe, dname):
    """
    Check if a probe has finished and also return the results.

    """
    url = dname.lower()
    task_result = probe.raw_results(url, get_client_ip(request))
    if task_result.done:
        return probe.rated_results(url)
    else:
        return dict(done=False)


def probestatus(request, probe, dname) -> ProbeTaskResult:
    """
    Check if a probe has finished.
    """
    url = dname.lower()
    return probe.check_results(url, get_client_ip(request))


def probestatuses(request, dname, probes):
    """
    Return the statuses (done or not) of the probes.

    """
    statuses = []
    for probe in probes:
        task_result = probestatus(request, probe, dname)
        statuses.append(
            {
                "name": probe.name,
                "done": task_result.done,
                "success": task_result.success,
            }
        )
    return statuses


def get_client_ip(request):
    """
    Get the client's IP address.

    If the server is proxied use the X_FORWARDED_FOR content.
    If the IP has multiple comma separated addresses, use the last one.
    """
    if settings.DJANGO_IS_PROXIED:
        ip = request.headers.get("x-forwarded-for", None)
    else:
        ip = request.META.get("REMOTE_ADDR")
    return ip.split(",")[-1].strip() if ip else None


def pretty_domain_name(dname):
    """
    Return a pretty printable domain name.

    If *dname* is in punnycode, decode it.

    """
    try:
        pretty = dname
        pretty = idna.decode(dname.encode("ascii"))
    except (UnicodeError, idna.IDNAError):
        pass
    return pretty


# Page calling/displaying JSON API
# URL: /(site|domain)/<dname>
def process(request, dname, template, probes, pageclass, pagetitle):
    addr = dname.lower()
    sorted_probes = probes.getset()
    done_count = 0
    no_javascript_redirect = request.path
    # Start the tests.
    # Also check if every test is done. In case of no-javascript we redirect
    # either to results or the same page.
    for probe in sorted_probes:
        task_result = probe.raw_results(addr, get_client_ip(request))
        if task_result.done:
            done_count += 1
    if done_count >= len(sorted_probes):
        no_javascript_redirect = "results"

    prettyaddr = pretty_domain_name(dname)

    return render(
        request,
        template,
        dict(
            addr=addr,
            prettyaddr=prettyaddr,
            pageclass=pageclass,
            pagetitle=f"{_(pagetitle)} {prettyaddr}",
            probes=sorted_probes,
            no_javascript_redirect=no_javascript_redirect,
            javascript_retries=get_javascript_retries(),
            javascript_timeout=settings.JAVASCRIPT_TIMEOUT * 1000,
        ),
    )


def get_javascript_retries():
    """
    Get number of javascript retries we are allowed to do before we reach
    the CACHE_TTL. Prevents infinitely registering slow tests.

    """
    return max(int(settings.CACHE_TTL / settings.JAVASCRIPT_TIMEOUT) - 2, 0)


def add_registrar_to_report(report):
    """
    Add the registrar information from the DNSSEC test to the report.

    """
    if report.registrar:
        return

    if isinstance(report.dnssec.report, dict) and report.dnssec.report.get("dnssec_exists"):
        registrar = report.dnssec.report["dnssec_exists"]["tech_data"]
        registrar = registrar[0][1]
        report.registrar = registrar
        report.save()


def add_score_to_report(report, score):
    """
    Add score to report if there is none.

    """
    if report.score is None:
        report.score = score
        report.save()


def update_report_with_registrar_and_score(report, probes):
    """
    Adds registrar information (from DNSSEC test if any) and score
    to a newly created report.

    """
    probe_reports = probes.get_probe_reports(report)
    add_registrar_to_report(report)
    score = probes.count_probe_reports_score(probe_reports)
    add_score_to_report(report, score)


def get_hof_cache(cache_id, count):
    cached_data = cache.get(cache_id, None)
    if cached_data is None:
        return "…", 0, []
    return (cached_data["date"], cached_data["count"], cached_data["data"][:count])


def get_hof_manual(manual):
    hof_entries = []
    try:
        with open(settings.MANUAL_HOF[manual]["entries_file"], encoding="utf-8") as f:
            hof_entries = yaml.load(f, Loader=yaml.Loader)
    except Exception:
        log.exception("failed to load manual hof")

    random.shuffle(hof_entries)
    return (len(hof_entries), hof_entries)


def get_retest_time(report):
    time_delta = timezone.make_aware(datetime.now()) - report.timestamp
    return int(max(0, settings.CACHE_TTL - time_delta.total_seconds()))


def get_valid_domain_web(dname, timeout=5):
    dname = validate_dname(dname)
    if dname is None:
        return None

    for qtype in (RdataType.A, RdataType.AAAA):
        try:
            dns_resolve(dname, qtype)
            return dname
        except (NoNameservers, NoAnswer, NXDOMAIN, LifetimeTimeout, dns.name.EmptyLabel):
            pass
    log.debug(f"{dname}: Could not retrieve A/AAAA record")
    return None


def get_valid_domain_mail(mailaddr, timeout=5):
    dname = validate_dname(mailaddr)
    if dname is None:
        return None

    try:
        dns_resolve_soa(dname)
    except (NXDOMAIN, Timeout):
        return None
    except NoAnswer:
        # We're fine with it if any record exists
        pass

    return dname


def redirect_invalid_domain(request, domain_type):
    if domain_type == "domain":
        return HttpResponseRedirect("/test-site/?invalid")
    elif domain_type == "mail":
        return HttpResponseRedirect("/test-mail/?invalid")
    else:
        return HttpResponseRedirect("/")


class SafeHttpResponseRedirect(HttpResponseRedirect):
    """
    This light wrapper around HttpResponseRedirect refuses redirects to
    other hosts or schemes. It should be used for any case where part
    of the URL may be based on user input.
    """

    def __init__(self, redirect_to, *args, **kwargs):
        super().__init__(redirect_to, *args, **kwargs)
        allowed_hosts = []
        for host in settings.ALLOWED_HOSTS:
            for optionalIPv6 in ["", ".ipv6"]:
                for optionalConn in ["", ".conn"]:
                    allowed_hosts.append(optionalConn + optionalIPv6 + host)
                    for language_code, language_name in settings.LANGUAGES:
                        allowed_hosts.append(language_code + optionalConn + optionalIPv6 + host)

        if not settings.DEBUG and not url_has_allowed_host_and_scheme(redirect_to, allowed_hosts=allowed_hosts):
            raise DisallowedRedirect("Unsafe redirect to URL: %s" % redirect_to)
