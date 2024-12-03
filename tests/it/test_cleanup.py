from django.core.management import call_command
from checks.models import DomainTestIpv6, DomainTestReport
import datetime
import pytest


def test_cleanup_aborted_or_periodic_test_results(db):
    """Make sure that test results with a report are deleted on cleanup, but not if they are recent."""
    ipv6_no_report = DomainTestIpv6(domain="example.com", report="{}")
    ipv6_no_report.save()
    ipv6_no_report.timestamp = datetime.datetime.now() - datetime.timedelta(seconds=200)
    ipv6_no_report.save()

    ipv6_report = DomainTestIpv6(domain="example.com", report="{}")
    ipv6_report.save()
    ipv6_report.timestamp = datetime.datetime.now() - datetime.timedelta(seconds=200)
    ipv6_report.save()

    ipv6_no_report_recent = DomainTestIpv6(domain="example.com", report="{}")
    ipv6_no_report_recent.save()

    ipv6_report_recent = DomainTestIpv6(domain="example.com", report="{}")
    ipv6_report_recent.save()

    report = DomainTestReport(domain="example.com", ipv6=ipv6_report)
    report.save()

    # run cleanup
    call_command("database_cleanup")

    with pytest.raises(DomainTestIpv6.DoesNotExist):
        ipv6_no_report.refresh_from_db()

    ipv6_report.refresh_from_db()
    assert ipv6_report

    ipv6_no_report_recent.refresh_from_db()
    assert ipv6_no_report_recent

    ipv6_report_recent.refresh_from_db()
    assert ipv6_report_recent
