# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
import re
import json

from django.conf import settings
from django.shortcuts import render
from django.http import HttpResponseRedirect, HttpResponse
from django.utils.translation import ugettext as _

from checks.models import MailTestIpv6, MailTestDnssec, MailTestAuth
from checks.models import MailTestTls, MailTestReport
from checks.probes import mailprobes
from checks.views.shared import proberesults, process, pretty_domain_name
from checks.views.shared import redirect_invalid_domain, add_score_to_report
from checks.views.shared import get_valid_domain_mail, add_registrar_to_report
from checks.views.shared import get_valid_domain_web, get_retest_time
from checks.views.shared import probestatuses

regex_mailaddr = (
    r'([a-zA-Z0-9]{0,61}@)?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+'
    '(?:[a-zA-Z]{2,63}|xn--[a-zA-Z0-9]+)')


# Entrance after form submission.
# URL: /mail/
def index(request, *args):
    try:
        url = request.POST.get('url', '').strip()
        return validate_domain(request, url)
    except KeyError:
        return HttpResponseRedirect('/')


# Request to /mail/<domain> without matching domain regex
# might be valid unicode domain, convert to punycode and validate again
def validate_domain(request, mailaddr):
    valid_domain = get_valid_domain_mail(mailaddr.lower().split("@")[-1])
    if valid_domain is None:
        return redirect_invalid_domain(request, "mail")

    return HttpResponseRedirect('/mail/{}/'.format(valid_domain))


def mailprocess(request, mailaddr):
    mailaddr = mailaddr.lower().split("@")[-1]
    return process(
        request, mailaddr, 'mail.html', mailprobes,
        "test-in-progress", "mail pagetitle")


def create_report(domain, ipv6, dnssec, auth, tls):
    report = MailTestReport(
        domain=domain,
        ipv6=ipv6,
        dnssec=dnssec,
        auth=auth,
        tls=tls)
    report.save()
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
        request, 'mail-results.html',
        dict(
            pageclass="emailtest",
            pagetitle="{} {}".format(
                _("mail pagetitle"), prettyaddr),
            addr=addr,
            prettyaddr=prettyaddr,
            permalink=request.build_absolute_uri(
                "/mail/{}/{}/".format(addr, str(report.id))),
            permadate=report.timestamp,
            retest_time=retest_time,
            retest_link=request.build_absolute_uri("/mail/{}/".format(addr)),
            webtest_direct=webtest_direct,
            mailtest_direct=mailtest_direct,
            probes=probe_reports,
            score=report.score,
            report=report,
            registrar=report.registrar))


# URL: /mail/<dname>/results/
def resultscurrent(request, mailaddr):
    addr = mailaddr.lower().split("@")[-1]
    # Get latest test results
    try:
        ipv6 = MailTestIpv6.objects.filter(domain=addr).order_by('-id')[0]
        dnssec = MailTestDnssec.objects.filter(domain=addr).order_by('-id')[0]
        auth = MailTestAuth.objects.filter(domain=addr).order_by('-id')[0]
        tls = MailTestTls.objects.filter(domain=addr).order_by('-id')[0]
    except IndexError:
        return HttpResponseRedirect("/mail/{}/".format(addr))

    # Do we already have a testreport for the latest results
    # (needed for persisent url-thingy)?
    try:
        report = ipv6.mailtestreport_set.order_by('-id')[0]
        if (not report.id == dnssec.mailtestreport_set.order_by('-id')[0].id
                == auth.mailtestreport_set.order_by('-id')[0].id
                == tls.mailtestreport_set.order_by('-id')[0].id):
            report = create_report(addr, ipv6, dnssec, auth, tls)
    except IndexError:
        # one of the test results is not yet related to a report,
        # create one
        report = create_report(addr, ipv6, dnssec, auth, tls)

    return HttpResponseRedirect("/mail/{}/{}/".format(addr, report.id))


# URL: /mail/<dname>/<reportid>/
def resultsstored(request, dname, id):
    """
    Render the results.
    If the report id is not found redirect to the home page.
    If the report id belongs to dated results start a new test.

    """
    if (settings.DATED_REPORT_ID_THRESHOLD_MAIL
            and int(id) < settings.DATED_REPORT_ID_THRESHOLD_MAIL):
        return HttpResponseRedirect("/mail/{}/".format(dname))

    try:
        report = MailTestReport.objects.get(id=id)
        if report.domain == dname:
            return resultsrender(report.domain, report, request)
        else:
            return HttpResponseRedirect('/')
    except MailTestReport.DoesNotExist:
        return HttpResponseRedirect('/')


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
