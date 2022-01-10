from django.core.management.base import BaseCommand

from checks.tasks.ipv6 import web


class Command(BaseCommand):
    help = "Perform a manual ipv6 test to internet.nl, to check the workings of the ipv6 scanner."

    def handle(self, *args, **options):
        print("Performing ipv6 test web scan")
        answers = web("internet.nl")
        print(answers)
