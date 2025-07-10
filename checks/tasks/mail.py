# Copyright: 2022, ECP, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
import time
from urllib.parse import urlparse

import idna
from celery import shared_task
from celery.exceptions import SoftTimeLimitExceeded
from django.conf import settings
from django.core.cache import cache

from dns.exception import DNSException
from dns.resolver import NoAnswer, NXDOMAIN

from checks import DMARC_NON_SENDING_POLICY, DMARC_NON_SENDING_POLICY_ORG, SPF_NON_SENDING_POLICY, categories, scoring
from checks.http_client import http_get
from checks.models import DmarcPolicyStatus, MailTestAuth, SpfPolicyStatus
from checks.resolver import dns_resolve_txt, dns_resolve_spf
from checks.tasks.dispatcher import check_registry, post_callback_hook
from checks.tasks.dmarc_parser import parse as dmarc_parse
from checks.tasks.spf_parser import parse as spf_parse
from interface import batch, batch_shared_task, redis_id
from internetnl import log


@shared_task(bind=True)
def mail_callback(self, results, addr, req_limit_id):
    category = categories.MailAuth()
    mtauth = callback(results, addr, category)
    # Always calculate scores on saving.
    from checks.probes import mail_probe_auth

    mail_probe_auth.rated_results_by_model(mtauth)
    post_callback_hook(req_limit_id, self.request.id)
    return results


@batch_shared_task(bind=True)
def batch_mail_callback(self, results, addr):
    category = categories.MailAuth()
    mtauth = callback(results, addr, category)
    # Always calculate scores on saving.
    from checks.probes import batch_mail_probe_auth

    batch_mail_probe_auth.rated_results_by_model(mtauth)
    batch.scheduler.batch_callback_hook(mtauth, self.request.id)


mail_registered = check_registry("mail_auth", mail_callback)
batch_mail_registered = check_registry("batch_mail_auth", batch_mail_callback)


@mail_registered
@shared_task(
    bind=True,
    soft_time_limit=settings.SHARED_TASK_SOFT_TIME_LIMIT_LOW,
    time_limit=settings.SHARED_TASK_TIME_LIMIT_LOW,
)
def dmarc(self, url, *args, **kwargs):
    return do_dmarc(url, *args, **kwargs)


@batch_mail_registered
@batch_shared_task(
    bind=True,
    soft_time_limit=settings.BATCH_SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.BATCH_SHARED_TASK_TIME_LIMIT_HIGH,
)
def batch_dmarc(self, url, *args, **kwargs):
    return do_dmarc(url, *args, **kwargs)


@mail_registered
@shared_task(
    bind=True,
    soft_time_limit=settings.SHARED_TASK_SOFT_TIME_LIMIT_LOW,
    time_limit=settings.SHARED_TASK_TIME_LIMIT_LOW,
)
def dkim(self, url, *args, **kwargs):
    return do_dkim(url, *args, **kwargs)


@batch_mail_registered
@batch_shared_task(
    bind=True,
    soft_time_limit=settings.BATCH_SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.BATCH_SHARED_TASK_TIME_LIMIT_HIGH,
)
def batch_dkim(self, url, *args, **kwargs):
    return do_dkim(url, *args, **kwargs)


@mail_registered
@shared_task(
    bind=True,
    soft_time_limit=settings.SHARED_TASK_SOFT_TIME_LIMIT_LOW,
    time_limit=settings.SHARED_TASK_TIME_LIMIT_LOW,
)
def spf(self, url, *args, **kwargs):
    return do_spf(url, *args, **kwargs)


@batch_mail_registered
@batch_shared_task(
    bind=True,
    soft_time_limit=settings.BATCH_SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.BATCH_SHARED_TASK_TIME_LIMIT_HIGH,
)
def batch_spf(self, url, *args, **kwargs):
    return do_spf(url, *args, **kwargs)


def skip_dkim_for_non_sending_domain(mtauth):
    """
    If there is no DKIM, check if DMARC and SPF are hinting for a non email
    sending domain and skip the DKIM results.
    """
    is_org = mtauth.dmarc_record_org_domain
    if (
        not mtauth.dkim_available
        and mtauth.dmarc_available
        and mtauth.dmarc_policy_status == DmarcPolicyStatus.valid
        and (
            (is_org and DMARC_NON_SENDING_POLICY_ORG.match(mtauth.dmarc_record[0]))
            or (not is_org and DMARC_NON_SENDING_POLICY.match(mtauth.dmarc_record[0]))
        )
        and mtauth.spf_available
        and mtauth.spf_policy_status == SpfPolicyStatus.valid
        and SPF_NON_SENDING_POLICY.match(mtauth.spf_record[0])
    ):
        return True
    return False


def callback(results, addr, category):
    subtests = category.subtests
    mtauth = MailTestAuth(domain=addr)
    for testname, result in results:
        if testname == "dkim":
            dkim_available = result.get("available")
            mtauth.dkim_available = dkim_available
            mtauth.dkim_score = result.get("score")
            if dkim_available:
                subtests["dkim"].result_good()
            else:
                subtests["dkim"].result_bad()

        elif testname == "dmarc":
            dmarc_available = result.get("available")
            # You'd expect a single entry, but the field dmarc_record is actually a list
            dmarc_record = [result.get("record")]
            dmarc_score = result.get("score")
            dmarc_policy_status = result.get("policy_status")
            dmarc_policy_score = result.get("policy_score")
            dmarc_record_org_domain = result.get("org_domain")
            mtauth.dmarc_available = dmarc_available
            mtauth.dmarc_record = dmarc_record
            mtauth.dmarc_score = dmarc_score
            mtauth.dmarc_policy_status = dmarc_policy_status
            mtauth.dmarc_policy_score = dmarc_policy_score
            mtauth.dmarc_record_org_domain = dmarc_record_org_domain

            dmarc_domain = dmarc_record_org_domain or addr
            tech_data = [[r, dmarc_domain] for r in dmarc_record]

            if dmarc_available:
                subtests["dmarc"].result_good(tech_data)

                if dmarc_policy_status == DmarcPolicyStatus.valid:
                    subtests["dmarc_policy"].result_good()
                elif dmarc_policy_status == DmarcPolicyStatus.invalid_external:
                    subtests["dmarc_policy"].result_invalid_external(tech_data)
                else:
                    if dmarc_policy_status == DmarcPolicyStatus.invalid_syntax:
                        subtests["dmarc_policy"].result_bad_syntax(tech_data)
                    elif dmarc_policy_status == DmarcPolicyStatus.invalid_p_sp:
                        subtests["dmarc_policy"].result_bad_policy(tech_data)

            else:
                subtests["dmarc"].result_bad(tech_data)

        elif testname == "spf":
            spf_available = result.get("available")
            spf_record = result.get("record")
            spf_score = result.get("score")
            spf_policy_status = result.get("policy_status")
            spf_policy_score = result.get("policy_score")
            spf_policy_records = result.get("policy_records")
            mtauth.spf_available = spf_available
            mtauth.spf_record = spf_record
            mtauth.spf_score = spf_score
            mtauth.spf_policy_status = spf_policy_status
            mtauth.spf_policy_score = spf_policy_score
            mtauth.spf_policy_records = spf_policy_records
            if spf_available:
                subtests["spf"].result_good(spf_record)

                if spf_policy_status == SpfPolicyStatus.valid:
                    subtests["spf_policy"].result_good()
                else:
                    # Show the records in the encountered ordered.
                    # Erronoeous record last.
                    spf_records = spf_policy_records[::-1]
                    if spf_policy_status == SpfPolicyStatus.invalid_syntax:
                        subtests["spf_policy"].result_bad_syntax(spf_records)
                    elif spf_policy_status == SpfPolicyStatus.max_dns_lookups:
                        subtests["spf_policy"].result_bad_max_lookups(spf_records)
                    elif spf_policy_status == SpfPolicyStatus.invalid_all:
                        subtests["spf_policy"].result_bad_policy(spf_records)
                    elif spf_policy_status == SpfPolicyStatus.invalid_include:
                        subtests["spf_policy"].result_bad_include(spf_records)
                    elif spf_policy_status == SpfPolicyStatus.invalid_redirect:
                        subtests["spf_policy"].result_bad_redirect(spf_records)

            else:
                subtests["spf"].result_bad(spf_record)

    if skip_dkim_for_non_sending_domain(mtauth):
        mtauth.dkim_score = scoring.MAIL_AUTH_DKIM_PASS
        subtests["dkim"].result_no_email()

    mtauth.report = category.gen_report()
    mtauth.save()
    return mtauth


def do_dkim(url, *args, **kwargs):
    try:
        dns_resolve_txt(f"_domainkey.{url}")
        available = True
        score = scoring.MAIL_AUTH_DKIM_PASS
    except NoAnswer:
        available = True
        score = scoring.MAIL_AUTH_DKIM_PASS
    except NXDOMAIN:
        available = False
        score = scoring.MAIL_AUTH_DKIM_FAIL
    except DNSException:
        available = False
        score = scoring.MAIL_AUTH_DKIM_ERROR
    return "dkim", {"available": available, "score": score}


def do_spf(url, *args, **kwargs):
    try:
        spf_record = dns_resolve_spf(url)
        available = bool(spf_record)
        score = scoring.MAIL_AUTH_SPF_PASS if spf_record else scoring.MAIL_AUTH_SPF_FAIL
    except NXDOMAIN:
        spf_record = None
        available = False
        score = scoring.MAIL_AUTH_SPF_FAIL
    except DNSException:
        spf_record = None
        available = False
        score = scoring.MAIL_AUTH_SPF_ERROR

    policy_status = None
    policy_score = scoring.MAIL_AUTH_SPF_POLICY_FAIL
    policy_records = []

    if spf_record:
        policy_status, policy_score, _ = spf_check_policy(url, spf_record, policy_records=policy_records)

    result = dict(
        available=available,
        score=score,
        record=[spf_record] if spf_record else [],
        policy_status=policy_status,
        policy_score=policy_score,
        policy_records=policy_records,
    )

    return "spf", result


def spf_check_include_redirect(
    domain, term, policy_records, max_lookups, assignment_operator, bad_status, is_include=False
):
    """
    Check the 'include' and 'redirect' terms.

    If a record is found, check that record for syntax and efficiency.
    Respects the maximum DNS lookups.  Macros are not expanded and
    thus not followed.  Bad statuses are converted to the given
    `bad_status` except for the `SpfPolicyStatus.max_dns_lookups`.

    """
    left_lookups = max_lookups
    status = SpfPolicyStatus.valid
    score = scoring.MAIL_AUTH_SPF_POLICY_PASS
    if max_lookups < 0:
        status = SpfPolicyStatus.max_dns_lookups
        score = scoring.MAIL_AUTH_SPF_POLICY_PARTIAL

    if status == SpfPolicyStatus.valid:
        url = term.split(assignment_operator)[1].strip()
        # Don't expand macros.
        if "{" in url:
            return status, score, left_lookups

    if status == SpfPolicyStatus.valid:
        try:
            new_spf = dns_resolve_spf(url)
        except DNSException:
            status = bad_status
            score = scoring.MAIL_AUTH_SPF_POLICY_PARTIAL

    if status == SpfPolicyStatus.valid:
        status, score, left_lookups = spf_check_policy(
            url, new_spf, policy_records=policy_records, max_lookups=left_lookups, is_include=is_include
        )

    if status != SpfPolicyStatus.valid and status != SpfPolicyStatus.max_dns_lookups:
        status = bad_status

    return status, score, left_lookups


def spf_check_redirect(domain, term, policy_records, max_lookups):
    return spf_check_include_redirect(domain, term, policy_records, max_lookups, "=", SpfPolicyStatus.invalid_redirect)


def spf_check_include(domain, term, policy_records, max_lookups):
    return spf_check_include_redirect(
        domain, term, policy_records, max_lookups, ":", SpfPolicyStatus.invalid_include, is_include=True
    )


def spf_check_policy(domain, spf_record, policy_records, max_lookups=10, is_include=False):
    """
    Check the SPF policy for syntax and efficiency.

    Terms being checked: all, include, redirect.
    Respects the maximum number of 10 DNS lookups.

    """
    left_lookups = max_lookups
    log.debug("Left lookups: %s" % left_lookups)
    status = SpfPolicyStatus.valid
    score = scoring.MAIL_AUTH_SPF_POLICY_PASS
    parsed = spf_parse(spf_record)
    if not parsed:
        status = SpfPolicyStatus.invalid_syntax
        score = scoring.MAIL_AUTH_SPF_POLICY_FAIL

    elif not parsed.get("terms"):
        # Defaults to '?all'.
        status = SpfPolicyStatus.invalid_all
        score = scoring.MAIL_AUTH_SPF_POLICY_PARTIAL

    else:
        terms = []
        redirect_terms = []
        all_found = False
        for term in (t.lower() for t in parsed["terms"]):
            if term.startswith("redirect"):
                redirect_terms.append(term)
                left_lookups -= 1
            elif "include:" in term:
                terms.append(term)
                left_lookups -= 1
            elif "mx" in term:
                log.debug("mx found in term, reducing left_lookups with 1")
                left_lookups -= 1
            elif "ptr" in term:
                log.debug("ptr found in term, reducing left_lookups with 1")
                left_lookups -= 1
            elif "exists" in term:
                log.debug("exists found in term, reducing left_lookups with 1")
                left_lookups -= 1
            elif "a" == term:
                log.debug("a found in term, reducing left_lookups with 1")
                left_lookups -= 1
            elif term.endswith("all") and len(term) < 5:
                all_found = True

                # Check 'all'
                if term.startswith(("+", "a")) or (not is_include and term.startswith("?")):
                    status = SpfPolicyStatus.invalid_all
                    score = scoring.MAIL_AUTH_SPF_POLICY_PARTIAL
                break
            log.debug("Found term: %s, max lookups now %d" % (term, left_lookups))

        if status == SpfPolicyStatus.valid:
            # No 'all' and no 'redirect', the default is '?all', fail.
            # Not applicable to include records, as the result is just
            # not_match.
            if not is_include and not redirect_terms and not all_found:
                status = SpfPolicyStatus.invalid_all
                score = scoring.MAIL_AUTH_SPF_POLICY_PARTIAL

        if status == SpfPolicyStatus.valid:
            # Redirects must be last
            terms = terms + redirect_terms

            for term in terms:
                if status != SpfPolicyStatus.valid:
                    break

                if "redirect=" in term and not all_found:
                    status, score, left_lookups = spf_check_redirect(domain, term, policy_records, left_lookups)
                    # Only one redirect is followed
                    break

                elif "include:" in term:
                    status, score, left_lookups = spf_check_include(domain, term, policy_records, left_lookups)

    if status != SpfPolicyStatus.valid:
        policy_records.append((domain, spf_record))

    return status, score, left_lookups


def _dmarc_dns_lookup(url):
    dmarc_record = None
    continue_looking = False

    try:
        txt_records = dns_resolve_txt(f"_dmarc.{url}")
        dmarc_records = [t for t in txt_records if t.lower().startswith("v=dmarc1")]
        if len(dmarc_records) == 1:
            dmarc_record = dmarc_records[0]
            score = scoring.MAIL_AUTH_DMARC_PASS
        elif len(dmarc_records) > 1:
            score = scoring.MAIL_AUTH_DMARC_FAIL
        else:
            score = scoring.MAIL_AUTH_DMARC_FAIL
            continue_looking = True
    except NXDOMAIN:
        score = scoring.MAIL_AUTH_DMARC_FAIL
        continue_looking = True
    except NoAnswer:  # https://github.com/internetstandards/Internet.nl/issues/1808
        score = scoring.MAIL_AUTH_DMARC_FAIL
        continue_looking = True
    except DNSException:
        score = scoring.MAIL_AUTH_DMARC_ERROR

    return dmarc_record, score, continue_looking


def do_dmarc(url, *args, **kwargs):
    try:
        is_org_domain = False
        public_suffix_list = dmarc_get_public_suffix_list()
        if not public_suffix_list:
            # We don't have the public suffix list.
            # Raise SoftTimeLimitExceeded to easily fail the test.
            raise SoftTimeLimitExceeded

        dmarc_record, score, continue_looking = _dmarc_dns_lookup(url)

        if continue_looking:
            url = dmarc_find_organizational_domain(url, public_suffix_list)
            dmarc_record, score, continue_looking = _dmarc_dns_lookup(url)
            is_org_domain = True

        org_domain = is_org_domain and url or None

        if dmarc_record:
            policy_status, policy_score = dmarc_check_policy(dmarc_record, url, is_org_domain, public_suffix_list)
        else:
            policy_status = None
            policy_score = scoring.MAIL_AUTH_DMARC_POLICY_FAIL

        result = dict(
            available=bool(dmarc_record),
            score=score,
            record=dmarc_record,
            policy_status=policy_status,
            policy_score=policy_score,
            org_domain=org_domain,
        )

    # KeyError is due to score missing, happens in case of timeout on non resolving domain
    except (SoftTimeLimitExceeded, KeyError) as specific_exception:
        log.debug("Soft time limit exceeded: %s", specific_exception)
        result = dict(
            available=False,
            score=scoring.MAIL_AUTH_DMARC_ERROR,
            record=[],
            policy_status=None,
            policy_score=scoring.MAIL_AUTH_DMARC_POLICY_FAIL,
            org_domain=None,
        )

    return "dmarc", result


def dmarc_check_policy(dmarc_record, domain, is_org_domain, public_suffix_list):
    """
    Check the DMARC record for syntax and efficiency.

    If a `rua` and/or `ruf` directives are present and the domain
    listed is not the same as the domain being tested, verify the
    external destinations.

    """
    domain = domain.lower().rstrip(".")
    parsed = dmarc_parse(dmarc_record)
    status, score = dmarc_verify_sufficient_policy(parsed, is_org_domain, public_suffix_list)

    if status == DmarcPolicyStatus.valid and parsed.get("directives"):
        status, score = dmarc_verify_external_destinations(domain, parsed, public_suffix_list)
    return (status, score)


def dmarc_verify_sufficient_policy(parsed, is_org_domain, public_suffix_list):
    """
    Verify that the s=(sp=) policy is not 'none'.

    """
    status = DmarcPolicyStatus.valid
    score = scoring.MAIL_AUTH_DMARC_POLICY_PASS
    if not parsed:
        status = DmarcPolicyStatus.invalid_syntax
        score = scoring.MAIL_AUTH_DMARC_POLICY_FAIL

    request = None
    if status == DmarcPolicyStatus.valid:
        if not parsed.get("directives"):
            status = DmarcPolicyStatus.invalid_p_sp
            score = scoring.MAIL_AUTH_DMARC_POLICY_PARTIAL
        else:
            if is_org_domain:
                if not parsed["directives"].get("srequest") and not parsed["directives"].get("request"):
                    status = DmarcPolicyStatus.invalid_p_sp
                    score = scoring.MAIL_AUTH_DMARC_POLICY_PARTIAL
                else:
                    if parsed["directives"].get("srequest"):
                        request = parsed["directives"]["srequest"]
                    elif parsed["directives"].get("request"):
                        request = parsed["directives"]["request"]
            else:
                if not parsed["directives"].get("request"):
                    status = DmarcPolicyStatus.invalid_p_sp
                    score = scoring.MAIL_AUTH_DMARC_POLICY_PARTIAL
                else:
                    request = parsed["directives"]["request"]

            if request is not None:
                value = request.split("=")[1]
                if value.lower() == "none":
                    status = DmarcPolicyStatus.invalid_p_sp
                    score = scoring.MAIL_AUTH_DMARC_POLICY_PARTIAL
    return (status, score)


def _dmarc_get_ru_host(parsed):
    """
    Generator for returning the host for rua and ruf directives.

    """
    for directive in ("auri", "furi"):
        if parsed["directives"].get(directive):
            value = parsed["directives"][directive].split("=")[1]
            uris = value.split(",")
            for uri in uris:
                uri = urlparse(uri)
                if uri.netloc == "" and uri.path:
                    host = uri.path
                    if "@" in host:
                        host = host.split("@", 1)[1].split("!", 1)[0]
                    host = host.strip().lower().rstrip(".")
                    yield host


def dmarc_verify_external_destinations(domain, parsed, public_suffix_list):
    """
    Verify external destinations as per section 7.1 (RFC7489).

    """
    status = DmarcPolicyStatus.valid
    score = scoring.MAIL_AUTH_DMARC_POLICY_PASS
    domain_org = dmarc_find_organizational_domain(domain, public_suffix_list)
    for host in _dmarc_get_ru_host(parsed):
        host_org = dmarc_find_organizational_domain(host, public_suffix_list)
        if domain_org != host_org:
            ext_qname = f"{domain}._report._dmarc.{host}"
            is_dmarc = False
            try:
                txt_records = dns_resolve_txt(ext_qname)
                for txt in txt_records:
                    ru_parsed = dmarc_parse(txt)
                    if ru_parsed:
                        if is_dmarc:
                            # Second valid DMARC record, abort.
                            is_dmarc = False
                            break
                        # Need to check same host on rua/ruf.
                        for ru_host in _dmarc_get_ru_host(ru_parsed):
                            if host != ru_host:
                                is_dmarc = False
                                break
                        is_dmarc = True
            except DNSException:
                pass

            if not is_dmarc:
                status = DmarcPolicyStatus.invalid_external
                score = scoring.MAIL_AUTH_DMARC_POLICY_PASS
                break

    return (status, score)


def dmarc_find_organizational_domain(domain, public_suffix_list):
    """
    Find the organizational domain of the given domain.

    Uses mainly the algorithm found at https://publicsuffix.org/list/ to get
    the organizational domain. Could return "" if none is found.

    """
    # The algorithm could be more elaborate but this is simple and fast enough.
    organizational_domain = ""
    matching_rule = []
    matching_count = 0
    matching_exception = False
    labels = domain.split(".")[::-1]
    for rule, exception in public_suffix_list:
        if matching_exception and not exception:
            continue

        # We always need to have the whole rule available. zip (later) will
        # truncate to the shortest list.
        if len(rule) > len(labels):
            continue

        matched = 0
        for a, b in zip(rule, labels):
            if a in ("*", b):
                matched += 1
            else:
                break

        # The whole rule needs to match.
        if matched == len(rule):
            if exception:
                matching_rule = rule
                matching_count = matched
                matching_exception = exception
            elif matched > matching_count:
                matching_rule = rule
                matching_count = matched

    if matching_rule:
        if matching_exception:
            organizational_domain = ".".join(labels[: len(matching_rule)][::-1])
        elif len(labels) > len(matching_rule):
            organizational_domain = ".".join(labels[: matching_count + 1][::-1])
    # Default matching rule is "*"
    elif len(labels) > 1:
        organizational_domain = ".".join(labels[:2][::-1])

    return organizational_domain


def dmarc_fetch_public_suffix_list():
    """
    Fetch the list from the configured URL and parse it leaving out comments,
    empty lines and invalid lines.

    """
    public_suffix_list = []
    response = http_get(settings.PUBLIC_SUFFIX_LIST_URL)
    if response.status_code != 200 or not response.text:
        return public_suffix_list

    lines = response.text.split("\n")
    for line in lines:
        labels = []
        line = line.rstrip()
        if line and not line.startswith(("//", " ")):
            exception = False
            if line.startswith("!"):
                exception = True
                line = line[1:]
            # Convert to punnycode.
            # This is how we are going to compare domain names later.
            try:
                for label in line.split("."):
                    if label == "*":
                        labels.append(label)
                    else:
                        labels.append(idna.encode(label).decode("ascii"))
                public_suffix_list.append((labels[::-1], exception))
            except (UnicodeError, ValueError, idna.IDNAError):
                pass
    return public_suffix_list


def dmarc_get_public_suffix_list():
    """
    Return the parsed public suffix list.

    If it is not already in cache fetch it, parse it and store it in cache.
    Also make sure that only one task does the fetching and others wait for
    the list.

    """
    public_suffix_list_id = redis_id.psl_data.id
    public_suffix_list_ttl = redis_id.psl_data.ttl
    public_suffix_list_loading_id = redis_id.psl_loading.id
    public_suffix_list_loading_ttl = redis_id.psl_loading.ttl
    tries = 3
    while True:
        public_suffix_list = cache.get(public_suffix_list_id)
        if public_suffix_list or tries <= 0:
            return public_suffix_list

        is_loading = cache.get(public_suffix_list_loading_id)
        if is_loading:
            tries -= 1
            time.sleep(3)
            continue
        break

    if not is_loading:
        status = cache.add(public_suffix_list_loading_id, True, timeout=public_suffix_list_loading_ttl)
        if status:
            public_suffix_list = dmarc_fetch_public_suffix_list()
            if public_suffix_list:
                cache.set(public_suffix_list_id, public_suffix_list, timeout=public_suffix_list_ttl)
                cache.delete(public_suffix_list_loading_id)
        else:
            # Lost the race; call this again to wait for the list.
            public_suffix_list = dmarc_get_public_suffix_list()

    return public_suffix_list
