from django.core.management.base import BaseCommand

from checks.tasks.ipv6 import web
from django.conf import settings
import socket


class Command(BaseCommand):
    help = "Perform a manual ipv6 test to internet.nl, to check the workings of the ipv6 scanner."

    def add_arguments(self, parser):
        parser.add_argument(
            "--domain",
            type=str,
            default="internet.nl",
            nargs="?",
            help="Only show ciphers of a certain security level.",
        )

    def handle(self, *args, **options):
        domain = options.get("domain", "internet.nl")
        resolver = socket.gethostbyname(settings.RESOLVER_INTERNAL_VALIDATING)
        print(f"Performing ipv6 test web scan on {domain}. " f"Using unbound at: {resolver}.")
        answers = web(domain)
        print(answers)
