import logging
from typing import Dict, Callable, Optional

from django.conf import settings
from django.core.management.base import BaseCommand

from checks.tasks import ipv6, dnssec, mail, shared, appsecpriv, tls, rpki


log = logging.getLogger(__package__)

PROBES: Dict[str, Optional[Callable]] = {
    "ipv6_web": ipv6.web,
    "ipv6_ns": ipv6.ns,
    "ipv6_mx": ipv6.mx,
    "dnssec_web_is_secure": dnssec.web_is_secure,
    "dnssec_mail_is_secure": dnssec.mail_is_secure,
    "mail_dmarc": mail.dmarc,
    "mail_dkim": mail.dkim,
    "mail_spf": mail.spf,
    "shared_mail_get_servers": shared.mail_get_servers,
    "shared_resolve_a_aaaa": shared.resolve_a_aaaa,
    "appsecpriv_web_appsecpriv": appsecpriv.web_appsecpriv,
    "tls_web_cert": tls.web_cert,
    "tls_web_conn": tls.web_conn,
    "tls_web_http": tls.web_http,
    "tls_mail_smtp_starttls": tls.mail_smtp_starttls,
    "mail_rpki": rpki.mail_rpki,
    "web_rpki": rpki.web_rpki,
    "all": None,
}


class Command(BaseCommand):
    """Usage:

    source .venv/bin/activate
    python3 manage.py probe --probe=dnssec_web_is_secure --domain=internet.nl

    """

    help = "Launch a probe and retrieve the results. This allows for easier debugging of probes."

    def add_arguments(self, parser):
        parser.add_argument("--domain", type=str, default="internet.nl", nargs="?")
        parser.add_argument("--probe", type=str, default="ipv6_web", nargs="?", choices=PROBES.keys())

    def handle(self, *args, **options):
        domain = options.get("domain", "internet.nl")
        probe = options.get("probe", "ipv6_web")

        if probe == "all":
            run_all_probes(domain)
        else:
            run_probe(probe, domain)


def run_all_probes(domain):
    log.info(f"Performing all probes on {domain}.")
    for probe_name in PROBES.keys():
        if probe_name == "all":
            continue
        run_probe(probe_name, domain)
    log.info(f"Done with all probes on {domain}.")


def run_probe(probe: str, domain: str):
    log.info(f"Performing {probe} on {domain}.")

    if probe in ["tls_web_cert", "tls_web_conn", "tls_web_http", "appsecpriv_web_appsecpriv", "web_rpki"]:
        log.debug("First retrieving af_ip_pairs")
        af_ip_pairs = shared.resolve_a_aaaa(domain)
        log.debug(f"af_ip_pairs retrieved: {af_ip_pairs}")
        return_value = PROBES[probe](af_ip_pairs, domain)

    elif probe in ["tls_mail_smtp_starttls", "dnssec_mail_is_secure"]:
        log.debug("First retrieving mailservers")
        mailservers = shared.mail_get_servers(domain)
        log.debug(f"Mailservers retrieved: {mailservers}")
        return_value = PROBES[probe](mailservers, domain)

    elif probe in ["mail_rpki"]:
        log.debug("First retrieving mailserver IPs")
        mailservers = shared.resolve_mx(domain)
        log.debug(f"Mailserver IPs retrieved: {mailservers}")
        return_value = PROBES[probe](mailservers, domain)

    else:
        return_value = PROBES[probe](domain)

    log.info(f"Retrieved return value: {return_value}")
    log.info("Done")
