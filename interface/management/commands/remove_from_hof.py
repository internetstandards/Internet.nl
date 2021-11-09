from django.core.management.base import BaseCommand

from interface.models import DomainTestReport, MailTestReport


class Command(BaseCommand):
    help = (
        "Removes a domain from the Hall of Fame by removing the relevant 100% "
        "reports for that domain.")

    def info(self, text):
        if self.v_level:
            self.stdout.write(f"{text}")

    def debug(self, text):
        if self.v_level > 1:
            self.stdout.write(f"{text}")

    def remove_domain(self, domain):
        for model in DomainTestReport, MailTestReport:
            try:
                latest_non_100_report = model.objects.filter(
                    domain=domain, score__lt=100).order_by('-id')[0]
                id = latest_non_100_report.id
            except IndexError:
                id = 0

            res = model.objects.filter(
                domain=domain, id__gt=id, score=100).delete()

            if res[0] == 0:
                self.info(f'Nothing to remove for {domain} on {model}')
            else:
                self.info(f'Removed {domain} from {model}')

    def add_arguments(self, parser):
        parser.add_argument('domain', help="The domain to remove.")

    def handle(self, *args, **options):
        self.v_level = options['verbosity']
        self.remove_domain(options['domain'])
