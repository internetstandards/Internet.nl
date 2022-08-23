# Copyright: 2022, ECP, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
import json
import re

from django.core.cache import cache
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.utils.translation import ugettext as _

from checks.models import (
    AutoConfOption,
    DomainTestDnssec,
    DomainTestIpv6,
    DomainTestReport,
    WebTestAppsecpriv,
    WebTestTls,
    WebTestRpki,
)
from checks.probes import webprobes
from interface import redis_id, simple_cache_page
from interface.views.shared import (
    add_registrar_to_report,
    add_score_to_report,
    get_retest_time,
    get_valid_domain_mail,
    get_valid_domain_web,
    pretty_domain_name,
    proberesults,
    probestatuses,
    process,
    redirect_invalid_domain,
    update_report_with_registrar_and_score,
)

# Entrance after form submission.
# URL: /(site|domain)/
from internetnl import log


def index(request, *args):
    try:
        url = request.POST.get("url", "").strip()
        if url.endswith("/"):
            url = url[:-1]
        return validate_domain(request, url)
    except KeyError:
        return HttpResponseRedirect("/")


# Request to /site/<domain> without matching domain regex
# might be valid unicode domain, convert to punycode and validate again
def validate_domain(request, dname):
    valid_domain = get_valid_domain_web(dname)
    if valid_domain is None:
        return redirect_invalid_domain(request, "domain")

    return HttpResponseRedirect("/site/{}/".format(valid_domain))


def siteprocess(request, dname):
    return process(request, dname, "domain.html", webprobes, "test-in-progress", "domain pagetitle")


def create_report(domain, ipv6, dnssec, tls=None, appsecpriv=None, rpki=None):
    report = DomainTestReport(domain=domain, ipv6=ipv6, dnssec=dnssec, tls=tls, appsecpriv=appsecpriv, rpki=rpki)
    report.save()
    update_report_with_registrar_and_score(report, webprobes)
    return report


def get_direct_domains(address):
    webtest_direct = []
    # Add either the 'www.' version or the non 'www.' version, whichever we are
    # not, to the direct links.
    if address.startswith("www."):
        domain = get_valid_domain_web(re.sub("^www.", "", address), timeout=2)
    else:
        domain = get_valid_domain_web("www." + address, timeout=2)
    if domain:
        webtest_direct.append(pretty_domain_name(domain))

    mailtest_direct = []
    # Add the current domain and the non 'www.' version, if applicable, to the
    # direct links.
    if address.startswith("www."):
        domain = get_valid_domain_mail(re.sub("^www.", "", address), timeout=2)
        if domain:
            mailtest_direct.append(pretty_domain_name(domain))
    domain = get_valid_domain_mail(address, timeout=2)
    if domain:
        mailtest_direct.append(pretty_domain_name(domain))

    return webtest_direct, mailtest_direct


def resultsrender(addr, report, request):
    probe_reports = webprobes.get_probe_reports(report)
    add_registrar_to_report(report)
    score = webprobes.count_probe_reports_score(probe_reports)
    add_score_to_report(report, score)
    retest_time = get_retest_time(report)
    webtest_direct, mailtest_direct = get_direct_domains(addr)
    prettyaddr = pretty_domain_name(addr)
    return render(
        request,
        "domain-results.html",
        dict(
            pageclass="websitetest",
            pagetitle="{} {}".format(_("domain pagetitle"), prettyaddr),
            addr=addr,
            prettyaddr=prettyaddr,
            permalink=request.build_absolute_uri("/site/{}/{}/".format(addr, str(report.id))),
            permadate=report.timestamp,
            retest_time=retest_time,
            retest_link=request.build_absolute_uri("/site/{}/".format(addr)),
            webtest_direct=webtest_direct,
            mailtest_direct=mailtest_direct,
            probes=probe_reports,
            score=report.score,
            report=report,
            registrar=report.registrar,
        ),
    )


# URL: /(site|domain)/<dname>/results/
def resultscurrent(request, dname):
    addr = dname.lower()
    # Get latest test results
    try:
        ipv6 = DomainTestIpv6.objects.filter(domain=addr).order_by("-id")[0]
        dnssec = DomainTestDnssec.objects.filter(domain=addr, maildomain_id=None).order_by("-id")[0]
        tls = WebTestTls.objects.filter(domain=addr).order_by("-id")[0]
        appsecpriv = WebTestAppsecpriv.objects.filter(domain=addr).order_by("-id")[0]
        rpki = WebTestRpki.objects.filter(domain=addr).order_by("-id")[0]

    except IndexError:
        # Domain not tested, go back to start test
        return HttpResponseRedirect("/site/{}/".format(addr))

    # Do we already have a testreport for the latest results (needed
    # for persisent url-thingy)?
    try:
        report = ipv6.domaintestreport_set.order_by("-id")[0]
        if (
            not report.id
            == dnssec.domaintestreport_set.order_by("-id")[0].id
            == tls.domaintestreport_set.order_by("-id")[0].id
            == appsecpriv.domaintestreport_set.order_by("-id")[0].id
            == rpki.domaintestreport_set.order_by("-id")[0].id
        ):
            report = create_report(addr, ipv6, dnssec, tls, appsecpriv, rpki)
    except IndexError:
        # one of the test results is not yet related to a report,
        # create one
        report = create_report(addr, ipv6, dnssec, tls, appsecpriv, rpki)
    return HttpResponseRedirect("/site/{}/{}/".format(addr, report.id))


# URL: /(site|domain)/<dname>/<reportid>/
@simple_cache_page
def resultsstored(request, dname, id):
    """
    Render the results.
    If the report id is not found redirect to the home page.
    If the report id belongs to dated results start a new test.

    """
    option = AutoConfOption.DATED_REPORT_ID_THRESHOLD_WEB
    cache_id = redis_id.autoconf.id.format(option.value)
    id_threshold = cache.get(cache_id)
    if id_threshold and int(id) <= id_threshold:
        return HttpResponseRedirect("/site/{}/".format(dname))

    try:
        report = DomainTestReport.objects.get(id=id)
        if report.domain == dname:
            return resultsrender(report.domain, report, request)
        else:
            return HttpResponseRedirect("/")
    except DomainTestReport.DoesNotExist:
        return HttpResponseRedirect("/")


# URL: /(site|domain)/(ipv6|dnssec|tls|appsecpriv)/<dname>/
def siteprobeview(request, probename, dname):
    results = proberesults(request, webprobes[probename], dname)
    return HttpResponse(json.dumps(results))


# URL: /(site|domain)/probes/<dname>/
def siteprobesstatus(request, dname):
    dname = dname.lower()
    statuses = probestatuses(request, dname, webprobes)
    log.debug("Probe status: %s", statuses)
    return HttpResponse(json.dumps(statuses))
