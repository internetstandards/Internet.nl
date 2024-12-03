from django.core.management.base import BaseCommand
from checks.models import BatchRequest, DomainTestIpv6, DomainTestDnssec, WebTestTls, WebTestAppsecpriv, WebTestRpki
import logging
import datetime
from django.conf import settings
from django.utils import timezone

log = logging.getLogger(__name__)


BATCH_PERIODIC_TESTS_PREFIX = "batch periodic tests"

TEST_REPORT_PROBE_MODELS = [DomainTestIpv6, DomainTestDnssec, WebTestTls, WebTestAppsecpriv, WebTestRpki]


class Command(BaseCommand):
    help = "Removes batch periodic test scan results and dangling probe results from database"

    def info(self, text):
        if self.v_level:
            self.stdout.write(f"{text}")

    def debug(self, text):
        if self.v_level > 1:
            self.stdout.write(f"{text}")

    def handle(self, *args, **options):
        logging.basicConfig(level=logging.INFO if options["verbosity"] > 0 else logging.ERROR)

        count, _ = BatchRequest.objects.filter(name__startswith=BATCH_PERIODIC_TESTS_PREFIX).delete()
        log.info("Deleted %s BatchRequest objects from batch periodic tests.", count)

        timestamp_recent_probes = timezone.make_aware(datetime.datetime.now()) - datetime.timedelta(
            seconds=int(settings.CACHE_TTL)
        )

        for model in TEST_REPORT_PROBE_MODELS:
            # >>> print(DomainTestIpv6.objects.filter(domaintestreport__isnull=True).values_list('id').query)
            # SELECT "checks_domaintestipv6"."id" FROM "checks_domaintestipv6" LEFT OUTER JOIN "checks_domaintestreport"
            #  ON ("checks_domaintestipv6"."id" = "checks_domaintestreport"."ipv6_id")
            #  WHERE "checks_domaintestreport"."id" IS NULL

            # find all test probe results that have no report associated, but not to recent because
            # those might be unfinished tests
            count, _ = model.objects.filter(
                domaintestreport__isnull=True, timestamp__lt=timestamp_recent_probes
            ).delete()
            log.info("Deleted %s probes that don't have an associated report.", count)
