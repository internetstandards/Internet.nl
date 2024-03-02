# Copyright: 2022, ECP, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
import json
import re

from django.conf import settings
from django.core.cache import cache
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.utils.translation import gettext as _

from checks.models import (
    AutoConfOption,
    MailTestAuth,
    MailTestDnssec,
    MailTestIpv6,
    MailTestReport,
    MailTestTls,
    MailTestRpki,
)
from checks.probes import mailprobes
from interface import redis_id
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
from internetnl import log

regex_mailaddr = (
    r"([a-zA-Z0-9]{0,61}@)?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+" "(?:[a-zA-Z]{2,63}|xn--[a-zA-Z0-9]+)"
)


# Entrance after form submission.
# URL: /mail/
def index(request, *args):
    try:
        url = request.POST.get("url", "").strip()
        return validate_domain(request, url)
    except KeyError:
        return HttpResponseRedirect("/")


# Request to /mail/<domain> without matching domain regex
# might be valid unicode domain, convert to punycode and validate again
def validate_domain(request, mailaddr):
    valid_domain = get_valid_domain_mail(mailaddr.lower().split("@")[-1])
    if valid_domain is None:
        return redirect_invalid_domain(request, "mail")

    return HttpResponseRedirect(f"/mail/{valid_domain}/")


def mailprocess(request, mailaddr):
    mailaddr = mailaddr.lower().split("@")[-1]
    return process(request, mailaddr, "mail.html", mailprobes, "test-in-progress", "mail pagetitle")


def create_report(domain, ipv6, dnssec, auth, tls, rpki):
    report = MailTestReport(domain=domain, ipv6=ipv6, dnssec=dnssec, auth=auth, tls=tls, rpki=rpki)
    report.save()
    update_report_with_registrar_and_score(report, mailprobes)
    return report


def get_direct_domains(address):
    webtest_direct = []
    # Add both the 'www.' and the non 'www.' versions to the direct links.
    domain = get_valid_domain_web(address)
    if domain:
        webtest_direct.append(pretty_domain_name(domain))

    if address.startswith("www."):
        domain = get_valid_domain_web(re.sub("^www.", "", address))
    else:
        domain = get_valid_domain_web("www." + address)
    if domain:
        webtest_direct.append(pretty_domain_name(domain))

    mailtest_direct = []
    # Add the non 'www.' version to the direct links if we are testing the
    # 'www.' version.
    if address.startswith("www."):
        domain = get_valid_domain_mail(re.sub("^www.", "", address))
        if domain:
            mailtest_direct.append(pretty_domain_name(domain))

    return webtest_direct, mailtest_direct


def resultsrender(addr, report, request):
    probe_reports = mailprobes.get_probe_reports(report)
    add_registrar_to_report(report)
    score = mailprobes.count_probe_reports_score(probe_reports)
    add_score_to_report(report, score)
    retest_time = get_retest_time(report)
    webtest_direct, mailtest_direct = get_direct_domains(addr)
    prettyaddr = pretty_domain_name(addr)
    return render(
        request,
        "mail-results.html",
        dict(
            pageclass="emailtest",
            pagetitle="{} {}".format(_("mail pagetitle"), prettyaddr),
            addr=addr,
            prettyaddr=prettyaddr,
            permalink=request.build_absolute_uri(f"/mail/{addr}/{str(report.id)}/"),
            permadate=report.timestamp,
            retest_time=retest_time,
            retest_link=request.build_absolute_uri(f"/mail/{addr}/"),
            webtest_direct=webtest_direct,
            mailtest_direct=mailtest_direct,
            probes=probe_reports,
            score=report.score,
            report=report,
            registrar=report.registrar,
        ),
    )


# URL: /mail/<dname>/results/
def resultscurrent(request, mailaddr):
    # Normalize the domain name to lower case and remove everything up to (including) the @.
    addr = mailaddr.lower().split("@")[-1]
    # Get latest test results
    checks_current = {}
    # Names of the tests in the checks_current dictionary must be the same as the
    try:
        if settings.INTERNET_NL_CHECK_SUPPORT_IPV6:
            checks_current["ipv6"] = MailTestIpv6.objects.filter(domain=addr).order_by("-id")[0]
        if settings.INTERNET_NL_CHECK_SUPPORT_DNSSEC:
            checks_current["dnssec"] = MailTestDnssec.objects.filter(domain=addr).order_by("-id")[0]
        if settings.INTERNET_NL_CHECK_SUPPORT_TLS:
            checks_current["tls"] = MailTestTls.objects.filter(domain=addr).order_by("-id")[0]
        if settings.INTERNET_NL_CHECK_SUPPORT_RPKI:
            checks_current["rpki"] = MailTestRpki.objects.filter(domain=addr).order_by("-id")[0]
        if settings.INTERNET_NL_CHECK_SUPPORT_MAIL:
            checks_current["auth"] = MailTestAuth.objects.filter(domain=addr).order_by("-id")[0]
    except IndexError:
        log.exception("Test not complete")
        # Domain not tested, go back to start test
        return HttpResponseRedirect(f"/mail/{addr}/")

    # Do we already have a testreport for the latest results (needed
    # for persisent url-thingy)?
    try:
        first_check = list(checks_current.values())[0]
        report = first_check.mailtestreport_set.order_by("-id")[0]
        # make sure that all the checks are assigned to the same report_id
        # and create a new report if needed.
        for check in checks_current.values():
            if report.id != check.mailtestreport_set.order_by("-id")[0].id:
                # create_report(domain, ipv6, dnssec, tls=None, appsecpriv=None, rpki=None):
                report = create_report(
                    addr,  # domain
                    ipv6=checks_current.get("ipv6"),
                    dnssec=checks_current.get("dnssec"),
                    tls=checks_current.get("tls"),
                    auth=checks_current.get("auth"),
                    rpki=checks_current.get("rpki"),
                )
    except IndexError:
        # one of the test results is not yet related to a report, create one
        report = create_report(
            addr,
            ipv6=checks_current.get("ipv6"),
            dnssec=checks_current.get("dnssec"),
            tls=checks_current.get("tls"),
            auth=checks_current.get("auth"),
            rpki=checks_current.get("rpki"),
        )

    return HttpResponseRedirect(f"/mail/{addr}/{report.id}/")


# URL: /mail/<dname>/<reportid>/
def resultsstored(request, dname, id):
    """
    Render the results.
    If the report id is not found redirect to the home page.
    If the report id belongs to dated results start a new test.

    """
    option = AutoConfOption.DATED_REPORT_ID_THRESHOLD_MAIL
    cache_id = redis_id.autoconf.id.format(option.value)
    id_threshold = cache.get(cache_id)
    if id_threshold and int(id) <= id_threshold:
        return HttpResponseRedirect(f"/mail/{dname}/")

    try:
        report = MailTestReport.objects.get(id=id)
        if report.domain == dname:
            return resultsrender(report.domain, report, request)
        else:
            return HttpResponseRedirect("/")
    except MailTestReport.DoesNotExist:
        return HttpResponseRedirect("/")


# URL: /mail/(ipv6|dnssec|auth|tls)/<dname>/
def mailprobeview(request, probename, mailaddr):
    mailaddr = mailaddr.lower().split("@")[-1]
    results = proberesults(request, mailprobes[probename], mailaddr)
    return HttpResponse(json.dumps(results))


# URL: /mail/probes/<dname>/
def siteprobesstatus(request, dname):
    dname = dname.lower()
    statuses = probestatuses(request, dname, mailprobes)
    return HttpResponse(json.dumps(statuses))
