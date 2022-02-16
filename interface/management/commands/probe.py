import logging

from django.core.management.base import BaseCommand

from checks.tasks import ipv6, dnssec, mail, shared, appsecpriv, tls


def force_debug_logging():
    log = logging.getLogger(__package__)

    formatter = logging.Formatter("[%(asctime)s][%(name)s][%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S")
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    stream_handler.setLevel(logging.DEBUG)
    log.addHandler(stream_handler)
    log.setLevel(logging.DEBUG)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    logger = logging.getLogger("internetnl")
    logger.setLevel(logging.DEBUG)
    logger = logging.getLogger("django")
    logger.setLevel(logging.DEBUG)
    logger = logging.getLogger("celery")
    logger.setLevel(logging.DEBUG)

    return log


log = force_debug_logging()

probe_mapping = {
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
}


class Command(BaseCommand):
    """Usage:

    source .venv/bin/activate
    python3 manage.py probe --probe=dnssec_web_is_secure --domain=internet.nl

    """

    help = "Launch a probe and retrieve the results. This allows for easier debugging of probes."

    def add_arguments(self, parser):
        parser.add_argument(
            "--domain",
            type=str,
            default="internet.nl",
            nargs="?",
        )

        parser.add_argument("--probe", type=str, default="ipv6_web", nargs="?", choices=probe_mapping.keys())

    def handle(self, *args, **options):
        domain = options.get("domain", "internet.nl")
        probe = options.get("probe", "ipv6_web")
        log.info(f"Performing {probe} on {domain}.")

        if probe in ["tls_web_cert", "tls_web_conn", "tls_web_http"]:
            # todo: retrieve af ip pairs as first argument
            af_ip_pairs = ""
            return_value = probe_mapping[probe](af_ip_pairs, domain)
        if probe in ["tls_mail_smtp_starttls"]:
            # todo: retrieve mailservers as first argument
            mailservers = ""
            return_value = probe_mapping[probe](mailservers, domain)
        else:
            return_value = probe_mapping[probe](domain)

        log.info(f"Retrieved return value: {return_value}")
        log.info("Done")
