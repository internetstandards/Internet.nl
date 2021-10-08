# Copyright: 2021, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0

from collections import defaultdict

from celery import shared_task
from celery.exceptions import SoftTimeLimitExceeded
from django.conf import settings
from django.db import transaction

from . import SetupUnboundContext
from . import shared
from .dispatcher import check_registry, post_callback_hook
from .routing import Routinator, TeamCymruIPtoASN
from .. import categories
from .. import batch, batch_shared_task
from ..models import MailTestRpki, WebTestRpki, RpkiMxDomain, RpkiNsDomain
from ..models import RpkiWebDomain

from typing import Dict, List, Mapping, NewType, Tuple, Union
TestName = NewType('TestName', str)
TestResult = Dict[TestName, List[Dict[str, Union[Dict, List, str]]]]

# mapping services to models
model_map = dict(
    rpki_mail=RpkiMxDomain,
    rpki_ns=RpkiNsDomain,
    rpki_mx_ns=RpkiNsDomain,
    rpki_web=RpkiWebDomain)


@shared_task(bind=True)
def mail_callback(self, results, domain, req_limit_id):
    """Save results in the DB."""
    category = categories.MailTestRpki()
    maildomain, results = callback(results, domain, MailTestRpki(),
                                   "mailtestrpki", category)
    # Always calculate scores on saving.
    from ..probes import mail_probe_rpki
    mail_probe_rpki.rated_results_by_model(maildomain)
    post_callback_hook(req_limit_id, self.request.id)
    return results


@shared_task(bind=True)
def batch_mail_callback(self, results, domain, req_limit_id):
    """Save results in the DB."""
    category = categories.MailTestRpki()
    maildomain, results = callback(results, domain, MailTestRpki(),
                                   "mailtestrpki", category)
    # Always calculate scores on saving.
    from ..probes import batch_mail_probe_rpki
    batch_mail_probe_rpki.rated_results_by_model(maildomain)
    batch.scheduler.batch_callback_hook(maildomain, self.request.id)


@shared_task(bind=True)
def web_callback(self, results, domain, req_limit_id):
    """Save results in the DB."""
    category = categories.WebTestRpki()
    webdomain, results = callback(results, domain, WebTestRpki(),
                                  "webtestrpki", category)
    # Always calculate scores on saving.
    from ..probes import web_probe_rpki
    web_probe_rpki.rated_results_by_model(webdomain)
    post_callback_hook(req_limit_id, self.request.id)
    return results


@batch_shared_task(bind=True)
def batch_web_callback(self, results, domain):
    """Save results in the DB."""
    category = categories.WebRpki()
    webdomain = callback(results, domain, WebTestRpki(),
                         "webtestrpki", category)
    # Always calculate scores on saving.
    from ..probes import batch_web_probe_rpki
    batch_web_probe_rpki.rated_results_by_model(webdomain)
    batch.scheduler.batch_callback_hook(webdomain, self.request.id)


@transaction.atomic
def callback(results: Mapping[TestName, TestResult],
             domain, parent, parent_name, category):
    """Get the results, create the necessary tables and commit in the DB."""
    # parent stores the result for the domain under test
    parent.report = {}
    parent.domain = domain
    parent.save()

    for testname, serviceresults in results:
        for domain, routing in serviceresults.items():

            kw = {
                parent_name: parent,
                'domain': domain,
                'routing': routing,
            }

            # model stores the result per IP-address
            model = model_map.get(testname)(**kw)
            model.save()

    build_summary_report(parent, parent_name, category)

    return parent, results


web_registered = check_registry(
    "web_rpki", web_callback, shared.resolve_a_aaaa)
batch_web_registered = check_registry(
    "batch_web_rpki", batch_web_callback, shared.batch_resolve_a_aaaa)
mail_registered = check_registry(
    "mail_rpki", mail_callback, shared.resolve_mx)
batch_mail_registered = check_registry(
    "batch_mail_rpki", batch_mail_callback, shared.batch_resolve_mx)


@web_registered
@shared_task(
    bind=True,
    soft_time_limit=settings.SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext)
def web_rpki(self, af_ip_pairs, url, *args, **kwargs):
    """Celery task to perform rpki test on webservers for a domain."""
    return do_web_rpki(af_ip_pairs, url, self, *args, **kwargs)


@web_registered
@shared_task(
    bind=True,
    soft_time_limit=settings.SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext)
def ns_rpki(self, af_ip_pairs, url, *args, **kwargs):
    """Celery task to perform rpki test on nameservers for a domain."""
    return do_ns_rpki(url, self, *args, **kwargs)


@batch_web_registered
@shared_task(
    bind=True,
    soft_time_limit=settings.BATCH_SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.BATCH_SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext)
def batch_web_rpki(self, af_ip_pairs, url, *args, **kwargs):
    """Celery task to perform rpki test on webservers for a domain."""
    return do_web_rpki(af_ip_pairs, url, self, *args, **kwargs)


@batch_web_registered
@shared_task(
    bind=True,
    soft_time_limit=settings.BATCH_SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.BATCH_SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext)
def batch_ns_rpki(self, af_ip_pairs, url, *args, **kwargs):
    """Celery task to perform rpki test on nameservers for a domain."""
    return do_ns_rpki(af_ip_pairs, url, self, *args, **kwargs)


@mail_registered
@shared_task(
    bind=True,
    soft_time_limit=settings.SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext)
def mail_rpki(self, mx_ips_pairs, url, *args, **kwargs):
    """Celery task to perform rpki test on mailservers for a domain."""
    return do_mail_rpki(mx_ips_pairs, url, self, *args, **kwargs)


@mail_registered
@shared_task(
    bind=True,
    soft_time_limit=settings.SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext)
def mail_ns_rpki(self, mx_ips_pairs, url, *args, **kwargs):
    """Celery task to perform rpki test on nameservers for a domain.

    `@mail_registered` passes in mx_ips_pairs, which are not needed for this test.
    """
    return do_ns_rpki(url, self, *args, **kwargs)


@mail_registered
@shared_task(
    bind=True,
    soft_time_limit=settings.SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext)
def mail_mx_ns_rpki(self, mx_ips_pairs, url, *args, **kwargs):
    """Celery task to perform rpki test on nameservers for the mx records of a domain."""
    return do_mx_ns_rpki(mx_ips_pairs, url, self, *args, **kwargs)


@batch_mail_registered
@shared_task(
    bind=True,
    soft_time_limit=settings.BATCH_SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.BATCH_SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext)
def batch_mail_rpki(self, af_ip_pairs, url, *args, **kwargs):
    """Celery task to perform rpki test on mailservers for a domain."""
    return do_mail_rpki(url, self, *args, **kwargs)


@batch_mail_registered
@shared_task(
    bind=True,
    soft_time_limit=settings.BATCH_SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.BATCH_SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext)
def batch_mail_ns_rpki(self, mx_ips_pairs, url, *args, **kwargs):
    """Celery task to perform rpki test on nameservers for a domain.

    `@mail_registered` passes in mx_ips_pairs, which are not needed for this test.
    """
    return do_ns_rpki(url, self, *args, **kwargs)


@batch_mail_registered
@shared_task(
    bind=True,
    soft_time_limit=settings.BATCH_SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.BATCH_SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext)
def batch_mail_mx_ns_rpki(self, mx_ips_pairs, url, *args, **kwargs):
    """Celery task to perform rpki test on nameservers for the mx records of a domain."""
    return do_mx_ns_rpki(mx_ips_pairs, url, self, *args, **kwargs)


def report_exists(subtestname, category, domainset) -> None:
    """Generate a test report for the existence of ROAs."""
    def gen_tech_data(subtestname, domain, ip, validity) -> List[List[str]]:
        # Provide tech_data to generate a table of the following form
        # 
        # Server     | IP address  | ROA exists
        # -------------------------------------
        # example.nl | 192.168.0.1 | yes
        # example.nl | 192.168.0.2 | no

        if any(route['vrps'] for route in validity.values()):
            row = [domain, ip, "detail tech data yes"]

        else:
            row = [domain, ip, "detail tech data no"]

        return row

    failure_count = 0
    tech_data = []

    prev_domain = None
    for domain in domainset:
        for ip in domain.routing:
            # failure to validate, team cymru or routinator was unavailable
            if not ip['routes'] or not all(ip['validity'].values()):
                category.subtests[subtestname].result_not_tested()
                return

            tech_data.append(
                gen_tech_data(subtestname,
                              domain.domain if domain.domain != prev_domain else '...',
                              ip['ip'],
                              ip['validity']))

            if not any(route['vrps'] for route in ip['validity'].values()):
                failure_count += 1

            prev_domain = domain.domain

        prev_domain = domain.domain
    if not failure_count:
        category.subtests[subtestname].result_good(tech_data)
    else:
        category.subtests[subtestname].result_bad(tech_data)


def report_valid(subtestname, category, domainset) -> None:
    """Generate a test report based on Route Origin Validation.

    This compares routing data from BGP with published ROAs.
    """
    def gen_tech_data(subtestname, domain, asn, prefix, validity) -> List[str]:
        # Provide tech_data to generate a table of the following form
        # 
        # Server     | Route          | Origin  | Validation state
        # --------------------------------------------------------
        # example.nl | 192.168.0.0/16 | AS64496 | valid
        # example.nl | 192.168.0.0/26 | AS64497 | invalid

        if validity['state'] is None:
            state = "detail tech data not-tested"
        elif validity['state'] == 'invalid':
            state = f"{validity['state']} ({validity['reason']})"
        else:
            state = validity['state']

        return [domain, prefix, f"AS{asn}", state]

    failure_count = 0
    tech_data = []

    prev_domain = None
    for domain in domainset:
        for ip in domain.routing:
            # failure to validate, team cymru or routinator was unavailable
            if not ip['routes'] or not all(ip['validity'].values()):
                category.subtests[subtestname].result_not_tested()
                return

            for route, validity in ip['validity'].items():
                asn, prefix = route
                tech_data.append(
                    gen_tech_data(subtestname,
                                  domain.domain if domain.domain != prev_domain else '...',
                                  asn, prefix, validity))

                if validity['state'] != 'valid':
                    failure_count += 1

                prev_domain = domain.domain

    if not failure_count:
        category.subtests[subtestname].result_good(tech_data)
    else:
        category.subtests[subtestname].result_bad(tech_data)


def build_summary_report(parent, parent_name, category) -> None:
    """Build the summary report for all the IP addresses."""
    if parent_name == 'webtestrpki':
        webset = parent.webdomains.all().order_by('domain')
        nsset = parent.nsdomains.all().order_by('domain')

        report_exists('rpki_exists', category, webset)
        report_valid('rpki_valid', category, webset)
        report_exists('rpki_ns_exists', category, nsset)
        report_valid('rpki_ns_valid', category, nsset)

    elif parent_name == 'mailtestrpki':
        mxset = parent.mxdomains.all().order_by('domain')
        nsset = parent.nsdomains.all().order_by('domain')

        report_exists('rpki_exists', category, mxset)
        report_valid('rpki_valid', category, mxset)
        report_exists('rpki_ns_exists', category, nsset)
        report_valid('rpki_ns_valid', category, nsset)

    parent.report = category.gen_report()
    parent.save()


def do_web_rpki(af_ip_pairs, url, task,
                *args, **kwargs) -> Tuple[TestName, TestResult]:
    """Check webservers."""
    web = do_rpki(task, [(url, af_ip_pairs)], *args, **kwargs)

    return (TestName('rpki_web'), web)


def do_ns_rpki(url, task,
               *args, **kwargs) -> Tuple[TestName, TestResult]:
    """Check nameservers."""
    ns_ips_pairs = shared.do_resolve_ns(task, url)
    ns = do_rpki(task, ns_ips_pairs, *args, **kwargs)

    return (TestName('rpki_ns'), ns)


def do_mx_ns_rpki(mx_ips_pairs, url, task,
                  *args, **kwargs) -> Tuple[TestName, TestResult]:
    """Check nameservers for the mx record of a domain.

    These may or may not be the same as the nameservers for the domain itself.
    Only check additions.
    """
    mx_ns_ips_pairs = set()
    for mx, _ in mx_ips_pairs:
        for ns, ips in shared.do_resolve_ns(task, mx):
            mx_ns_ips_pairs.add((ns, tuple(ips)))

    # only look at distinct ns for mx
    ns_ips_pairs = ((ns, tuple(ips))
                    for ns, ips in shared.do_resolve_ns(task, url))
    mx_ns_ips_pairs -= set(ns_ips_pairs)

    mxns = do_rpki(task, mx_ns_ips_pairs, *args, **kwargs)

    return (TestName('rpki_mx_ns'), mxns)


def do_mail_rpki(mx_ips_pairs, url, task,
                 *args, **kwargs) -> Tuple[TestName, TestResult]:
    """Check mailservers."""
    mail = do_rpki(task, mx_ips_pairs, *args, **kwargs)

    return (TestName('rpki_mail'), mail)


def do_rpki(task, fqdn_ips_pairs, *args, **kwargs) -> TestResult:
    """Check IP-addresses for a service for the existence of valid Roas.

    Arguments:
    task -- celery task context
    fqdn_ips_pairs --   list of fqdn, af_ip_pairs pairs (to iterate over
                        multiple MX or NS records)
    """
    try:
        results = defaultdict(list)
        for fqdn, af_ip_pairs in fqdn_ips_pairs:
            for af_ip_pair in af_ip_pairs:
                # TODO: should we use concurrent.futures' map to do all this
                # concurrently? Without concurrency we're sequentially waiting
                # for both DNS resolution and http request completion.
                ip = af_ip_pair[1]
                result = {'ip': ip, 'routes': [], 'validity': {}}

                # fetch ASN, prefixes from BGP
                routeview = TeamCymruIPtoASN.from_bgp(task, ip)
                if routeview:
                    # and try to validate corresponding Roas
                    routeview.validate(task, Routinator)
                else:
                    # if BGP data is unavailable,
                    # we can still show the existence of Roas,
                    # but validation is meaningless
                    routeview = TeamCymruIPtoASN.from_rpki(
                                    task, Routinator, ip)
                result['routes'] = routeview.routes
                result['validity'] = routeview.validity

                results[fqdn].append(result)

    except SoftTimeLimitExceeded:
        for fqdn, af_ip_pairs in fqdn_ips_pairs:
            for af_ip_pair in af_ip_pairs:
                ip = af_ip_pair[1]
                d = {'ip': ip, 'routes': [], 'validity': {}}
                results[fqdn].append(d)

    return results
