# Copyright: 2022, ECP, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0

from collections import defaultdict

from celery import shared_task
from celery.exceptions import SoftTimeLimitExceeded
from django.conf import settings
from django.db import transaction
from celery.utils.log import get_task_logger

from interface import batch, batch_shared_task
from . import SetupUnboundContext
from . import shared
from .dispatcher import check_registry, post_callback_hook
from .routing import (
    BGPSourceUnavailableError,
    InvalidIPError,
    NoRoutesError,
    Routinator,
    TeamCymruIPtoASN,
    RelyingPartyUnvailableError,
)
from .. import categories, scoring
from ..models import (
    MailTestRpki,
    WebTestRpki,
    RpkiMxHost,
    RpkiMxNsHost,
    RpkiNsHost,
    RpkiWebHost,
)

from typing import Dict, List, Mapping, NewType, Tuple, Union

TestName = NewType("TestName", str)
TestResult = Dict[TestName, List[Dict[str, Union[Dict, List, str]]]]

logger = get_task_logger(__name__)

# mapping services to models
model_map = dict(
    rpki_mail=RpkiMxHost,
    rpki_ns=RpkiNsHost,
    rpki_mx_ns=RpkiMxNsHost,
    rpki_web=RpkiWebHost,
)


@shared_task(bind=True)
def mail_callback(self, results, domain, req_limit_id):
    """Save results in the DB."""
    category = categories.MailRpki()
    maildomain, results = callback(results, domain, MailTestRpki(), "mailtestrpki", category)
    # Always calculate scores on saving.
    from ..probes import mail_probe_rpki

    mail_probe_rpki.rated_results_by_model(maildomain)
    post_callback_hook(req_limit_id, self.request.id)
    return results


@shared_task(bind=True)
def batch_mail_callback(self, results, domain):
    """Save results in the DB."""
    category = categories.MailRpki()
    maildomain, results = callback(results, domain, MailTestRpki(), "mailtestrpki", category)
    # Always calculate scores on saving.
    from ..probes import batch_mail_probe_rpki

    batch_mail_probe_rpki.rated_results_by_model(maildomain)
    batch.scheduler.batch_callback_hook(maildomain, self.request.id)


@shared_task(bind=True)
def web_callback(self, results, domain, req_limit_id):
    """Save results in the DB."""
    category = categories.WebRpki()
    webdomain, results = callback(results, domain, WebTestRpki(), "webtestrpki", category)
    # Always calculate scores on saving.
    from ..probes import web_probe_rpki

    web_probe_rpki.rated_results_by_model(webdomain)
    post_callback_hook(req_limit_id, self.request.id)
    return results


@batch_shared_task(bind=True)
def batch_web_callback(self, results, domain):
    """Save results in the DB."""
    category = categories.WebRpki()
    webdomain, _ = callback(results, domain, WebTestRpki(), "webtestrpki", category)
    # Always calculate scores on saving.
    from ..probes import batch_web_probe_rpki

    batch_web_probe_rpki.rated_results_by_model(webdomain)
    batch.scheduler.batch_callback_hook(webdomain, self.request.id)


@transaction.atomic
def callback(results: Mapping[TestName, TestResult], domain, parent, parent_name, category):
    """Get the results, create the necessary tables and commit in the DB."""
    # parent stores the result for the domain under test
    parent.report = {}
    parent.domain = domain
    parent.save()

    for testname, serviceresults in results:
        for host, routing in serviceresults.items():
            kw = {
                parent_name: parent,
                "host": host,
                "routing": routing,
            }

            # model stores the result per IP-address
            model = model_map.get(testname)(**kw)
            model.save()

    build_summary_report(parent, parent_name, category)

    return parent, results


web_registered = check_registry("web_rpki", web_callback, shared.resolve_a_aaaa)
batch_web_registered = check_registry("batch_web_rpki", batch_web_callback, shared.batch_resolve_a_aaaa)
mail_registered = check_registry("mail_rpki", mail_callback, shared.resolve_mx)
batch_mail_registered = check_registry("batch_mail_rpki", batch_mail_callback, shared.batch_resolve_mx)


@web_registered
@shared_task(
    bind=True,
    soft_time_limit=settings.SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext,
)
def web_rpki(self, af_ip_pairs, url, *args, **kwargs):
    """Celery task to perform rpki test on webservers for a domain."""
    return do_web_rpki(af_ip_pairs, url, self, *args, **kwargs)


@mail_registered
@web_registered
@shared_task(
    bind=True,
    soft_time_limit=settings.SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext,
)
def ns_rpki(self, _, url, *args, **kwargs):
    """Celery task to perform rpki test on nameservers for a domain.

    `@web_registered` passes in af_ip_pairs, which are not needed for this test.
    `@mail_registered` passes in mx_ips_pairs, which are not needed for this test.
    """
    return do_ns_rpki(url, self, *args, **kwargs)


@batch_web_registered
@shared_task(
    bind=True,
    soft_time_limit=settings.BATCH_SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.BATCH_SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext,
)
def batch_web_rpki(self, af_ip_pairs, url, *args, **kwargs):
    """Celery task to perform rpki test on webservers for a domain."""
    return do_web_rpki(af_ip_pairs, url, self, *args, **kwargs)


@batch_web_registered
@batch_mail_registered
@shared_task(
    bind=True,
    soft_time_limit=settings.BATCH_SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.BATCH_SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext,
)
def batch_ns_rpki(self, _, url, *args, **kwargs):
    """Celery task to perform rpki test on nameservers for a domain.

    `@batch_web_registered` passes in af_ip_pairs, which are not needed for this test.
    `@batch_mail_registered` passes in mx_ips_pairs, which are not needed for this test.
    """
    return do_ns_rpki(url, self, *args, **kwargs)


@mail_registered
@shared_task(
    bind=True,
    soft_time_limit=settings.SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext,
)
def mail_rpki(self, mx_ips_pairs, url, *args, **kwargs):
    """Celery task to perform rpki test on mailservers for a domain."""
    return do_mail_rpki(mx_ips_pairs, url, self, *args, **kwargs)


@mail_registered
@shared_task(
    bind=True,
    soft_time_limit=settings.SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext,
)
def mail_mx_ns_rpki(self, mx_ips_pairs, url, *args, **kwargs):
    """Celery task to perform rpki test on nameservers for the mx records of a domain."""
    return do_mx_ns_rpki(mx_ips_pairs, url, self, *args, **kwargs)


@batch_mail_registered
@shared_task(
    bind=True,
    soft_time_limit=settings.BATCH_SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.BATCH_SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext,
)
def batch_mail_rpki(self, mx_ips_pairs, url, *args, **kwargs):
    """Celery task to perform rpki test on mailservers for a domain."""
    return do_mail_rpki(mx_ips_pairs, url, self, *args, **kwargs)


@batch_mail_registered
@shared_task(
    bind=True,
    soft_time_limit=settings.BATCH_SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.BATCH_SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext,
)
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
    base=SetupUnboundContext,
)
def batch_mail_mx_ns_rpki(self, mx_ips_pairs, url, *args, **kwargs):
    """Celery task to perform rpki test on nameservers for the mx records of a domain."""
    return do_mx_ns_rpki(mx_ips_pairs, url, self, *args, **kwargs)


def generate_roa_existence_report(subtestname, category, hostset) -> int:
    """Generate a test report for the existence of ROAs."""

    def gen_tech_data(host, ip, validity) -> List[List[str]]:
        # Provide tech_data to generate a table of the following form
        #
        # Server     | IP address  | ROA exists
        # -------------------------------------
        # example.nl | 192.168.0.1 | yes
        # example.nl | 192.168.0.2 | no

        if any(route["vrps"] for route in validity.values()):
            row = [host, ip, "detail tech data yes"]
        else:
            row = [host, ip, "detail tech data no"]

        return row

    missing_count = 0
    tech_data = []

    prev_host = None
    for host in hostset:
        for ip in host.routing:
            # failure to validate routinator was unavailable
            if RelyingPartyUnvailableError.__name__ in ip["errors"]:
                category.subtests[subtestname].result_validator_error()
                return

            tech_data.append(
                gen_tech_data(
                    host.host if host.host != prev_host else "...",
                    ip["ip"],
                    ip["validity"],
                )
            )

            if not any(route["vrps"] for route in ip["validity"].values()):
                missing_count += 1

            prev_host = host.host

    if not hostset:
        # no A/AAAA records exist
        category.subtests[subtestname].result_no_addresses()
    elif missing_count > 0:
        category.subtests[subtestname].result_bad(tech_data)
        return scoring.RPKI_EXISTS_FAIL
    else:
        category.subtests[subtestname].result_good(tech_data)
    return scoring.RPKI_EXISTS_GOOD


def generate_validity_report(subtestname, category, hostset) -> int:
    """Generate a test report based on Route Origin Validation.

    This compares routing data from BGP with published ROAs.
    """

    def gen_tech_data(host, asn, prefix, validity, errors) -> List[str]:
        # Provide tech_data to generate a table of the following form
        #
        # Server     | Route          | Origin  | Validation state
        # --------------------------------------------------------
        # example.nl | 192.168.0.0/16 | AS64496 | valid
        # example.nl | 192.168.0.0/26 | AS64497 | invalid
        # example.nl | 10.0.0.0/8     | ?       | not-tested

        asn = f"AS{asn}"

        if NoRoutesError.__name__ in errors:
            asn = "?"
            state = "detail tech data not-tested"
        elif validity["state"] == "invalid":
            state = f"{validity['state']} ({validity['reason']})"
        else:
            state = validity["state"]

        return [host, prefix, asn, state]

    count = 0
    not_routed_count = 0  # count of validation failures due to unavailability of routes
    invalid_count = 0  # count of validation resulting in 'invalid'
    not_valid_count = 0  # count of validations not resulting in 'valid'
    tech_data = []

    prev_host = None
    for host in hostset:
        for ip in host.routing:
            errors = ip["errors"]
            # failure to validate, team cymru or routinator was unavailable
            if RelyingPartyUnvailableError.__name__ in errors or BGPSourceUnavailableError.__name__ in errors:
                category.subtests[subtestname].result_validator_error()
                return

            for route, validity in ip["validity"].items():
                asn, prefix = route
                tech_data.append(
                    gen_tech_data(
                        host.host if host.host != prev_host else "...",
                        asn,
                        prefix,
                        validity,
                        errors,
                    )
                )

                count += 1
                if NoRoutesError.__name__ in errors:  # no BGP data available
                    not_routed_count += 1
                elif validity["state"] == "invalid":
                    invalid_count += 1
                elif validity["state"] != "valid":
                    not_valid_count += 1

                prev_host = host.host

    if count == 0:
        category.subtests[subtestname].result_no_addresses()
    elif invalid_count > 0:
        category.subtests[subtestname].result_invalid(tech_data)
        return scoring.RPKI_VALID_FAIL
    elif not_valid_count > 0:
        category.subtests[subtestname].result_bad(tech_data)
        return scoring.RPKI_VALID_FAIL
    elif not_routed_count == count:  # no BGP data for all IPs
        category.subtests[subtestname].result_not_routed(tech_data)
    else:
        category.subtests[subtestname].result_good(tech_data)
    return scoring.RPKI_VALID_GOOD


def build_summary_report(parent, parent_name, category) -> None:
    """Build the summary report for all the IP addresses."""
    if parent_name == "webtestrpki":
        webset = parent.webhosts.all().order_by("host")
        nsset = parent.nshosts.all().order_by("host")

        parent.web_exists_score = generate_roa_existence_report("web_rpki_exists", category, webset)
        parent.web_valid_score = generate_validity_report("web_rpki_valid", category, webset)
        parent.ns_exists_score = generate_roa_existence_report("ns_rpki_exists", category, nsset)
        parent.ns_valid_score = generate_validity_report("ns_rpki_valid", category, nsset)

    elif parent_name == "mailtestrpki":
        mxset = parent.mxhosts.all().order_by("host")
        nsset = parent.nshosts.all().order_by("host")
        mxnsset = parent.mxnshosts.all().order_by("host")

        parent.mail_exists_score = generate_roa_existence_report("mail_rpki_exists", category, mxset)
        parent.mail_valid_score = generate_validity_report("mail_rpki_valid", category, mxset)
        parent.ns_exists_score = generate_roa_existence_report("ns_rpki_exists", category, nsset)
        parent.ns_valid_score = generate_validity_report("ns_rpki_valid", category, nsset)
        parent.mx_ns_exists_score = generate_roa_existence_report("mail_mx_ns_rpki_exists", category, mxnsset)
        parent.mx_ns_valid_score = generate_validity_report("mail_mx_ns_rpki_valid", category, mxnsset)

    parent.report = category.gen_report()
    parent.save()


def do_web_rpki(af_ip_pairs, url, task, *args, **kwargs) -> Tuple[TestName, TestResult]:
    """Check webservers."""
    web = do_rpki(task, [(url, af_ip_pairs)], *args, **kwargs)

    return (TestName("rpki_web"), web)


def do_ns_rpki(url, task, *args, **kwargs) -> Tuple[TestName, TestResult]:
    """Check nameservers."""
    ns_ips_pairs = shared.do_resolve_ns_ips(task, url)
    ns = do_rpki(task, ns_ips_pairs, *args, **kwargs)

    return (TestName("rpki_ns"), ns)


def do_mx_ns_rpki(mx_ips_pairs, url, task, *args, **kwargs) -> Tuple[TestName, TestResult]:
    """Check nameservers for the mx record of a domain.

    These may or may not be the same as the nameservers for the domain itself.
    """
    mx_ns_ips_pairs = set()
    for mx, _ in mx_ips_pairs:
        for ns, ips in shared.do_resolve_ns_ips(task, mx):
            mx_ns_ips_pairs.add((ns, tuple(ips)))

    mxns = do_rpki(task, mx_ns_ips_pairs, *args, **kwargs)

    return (TestName("rpki_mx_ns"), mxns)


def do_mail_rpki(mx_ips_pairs, url, task, *args, **kwargs) -> Tuple[TestName, TestResult]:
    """Check mailservers."""
    mail = do_rpki(task, mx_ips_pairs, *args, **kwargs)

    return (TestName("rpki_mail"), mail)


def do_rpki(task, fqdn_ips_pairs, *args, **kwargs) -> TestResult:
    """Check IP-addresses for a service for the existence of valid Roas.

    Arguments:
        task: celery task context
        fqdn_ips_pairs: list of fqdn, af_ip_pairs pairs (to iterate over
                        multiple MX or NS records)
    """
    try:
        results = defaultdict(list)
        for fqdn, af_ip_pairs in fqdn_ips_pairs:
            for af_ip_pair in af_ip_pairs:
                ip = af_ip_pair[1]
                result = {"ip": ip, "routes": [], "validity": {}, "errors": []}

                try:
                    # fetch ASN, prefixes from BGP
                    routeview = TeamCymruIPtoASN.from_bgp(task, ip)
                except (InvalidIPError, BGPSourceUnavailableError) as e:
                    routeview = None
                    logger.error(repr(e))
                    result["errors"].append(e.__class__.__name__)

                try:
                    if routeview:
                        # if the ip is covered by a BGP announcement
                        # try to validate corresponding Roas
                        routeview.validate(task, Routinator)
                    else:
                        # if the ip is not covered by a BGP announcement
                        # we can still show the existence of Roas,
                        # but validation is meaningless
                        result["errors"].append(NoRoutesError.__name__)

                        routeview = TeamCymruIPtoASN.from_rpki(task, Routinator, ip)
                except RelyingPartyUnvailableError as e:
                    logger.error(repr(e))
                    result["errors"].append(e.__class__.__name__)
                else:
                    result["routes"] = routeview.routes
                    result["validity"] = routeview.validity

                results[fqdn].append(result)

    except SoftTimeLimitExceeded:
        for fqdn, af_ip_pairs in fqdn_ips_pairs:
            for af_ip_pair in af_ip_pairs:
                ip = af_ip_pair[1]
                d = {"ip": ip, "routes": [], "validity": {}, "errors": ["timeout"]}
                results[fqdn].append(d)

    return results
