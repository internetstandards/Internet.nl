# Copyright: 2022, ECP, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
from django.conf import settings
from django.conf.urls import url
from django.conf.urls.static import static

from interface import views
from interface.batch import BATCH_API_MAJOR_VERSION
from interface.batch import views as batch
from interface.views import connection, domain, mail, stats

regex_tld = r"(?:[a-zA-Z]{2,63}|xn--[a-zA-Z0-9]+)"
regex_dname = r"(?P<dname>([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+" + regex_tld + ")"
regex_testid = r"(?P<request_id>[a-zA-Z0-9]{1,35})"
regex_mailaddr = (
    r"(?P<mailaddr>([a-zA-Z0-9]{0,61}@)?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+" r"" + regex_tld + ")"
)

urlpatterns = [
    url(r"^$", views.indexpage),
    url(r"^statistics/(?P<start_date>[0-9]{8})/(?P<end_date>[0-9]{8})/$", stats.statistics),
    url(r"^disclosure/$", views.disclosurepage),
    url(r"^contact/$", views.indexpage),
    url(r"^copyright/$", views.copyrightpage),
    url(r"^privacy/$", views.privacypage),
    url(r"^faqs/$", views.faqindexpage),
    url(r"^faqs/report/$", views.faqreport, name="faqs_report"),
    url(r"^faqs/badges/$", views.faqbadges, name="faqs_badges"),
    url(r"^faqs/(?P<subject>[a-zA-Z0-9\-]{1,40})/$", views.faqarticlepage),
    url(r"^usage/$", views.indexpage),
    url(r"^about/$", views.aboutpage),
    url(r"^widget-site/$", views.widgetsitepage),
    url(r"^widget-mail/$", views.widgetmailpage),
    url(r"^blogs/$", views.blogindexpage),
    url(r"^blogs/(?P<addr>[a-zA-Z0-9\-]{1,40})/$", views.blogarticlepage),
    url(r"^blogs/(?P<author>[a-zA-Z0-9\-]{1,40})/(?P<article>[a-zA-Z0-9\-]{1,80})/$", views.blogarticlepage),
    url(r"^news/$", views.newsindexpage),
    url(r"^news/(?P<article>[a-zA-Z0-9\-]{1,80})/$", views.newsarticlepage),
    url(r"^articles/$", views.articleindexpage),
    url(r"^article/$", views.articlespage),
    url(r"^article/(?P<article>[a-zA-Z0-9\-]{1,80})/$", views.articlepage),
    url(r"^halloffame/$", views.hofchampionspage),
    url(r"^halloffame/web/$", views.hofwebpage),
    url(r"^halloffame/mail/$", views.hofmailpage),
    url(r"^test-connection/$", views.testconnectionpage),
    url(r"^connection/$", connection.index),
    url(r"^(connection|conn)/gettestid/$", connection.gettestid),
    url(rf"^(connection|conn)/finished/{regex_testid}$", connection.finished),
    url(rf"^(connection|conn)/addr-test/{regex_testid}/$", connection.addr_ipv6),
    url(rf"^(connection|conn)/{regex_testid}/results$", connection.results),
    url(r"^test-site/$", views.testsitepage),
    url(r"^(domain|site)/$", domain.index),
    url(rf"^(domain|site)/{regex_dname}/$", domain.siteprocess),
    url(rf"^(domain|site)/probes/{regex_dname}/$", domain.siteprobesstatus),
    url(rf"^(domain|site)/(?P<probename>(ipv6|tls|dnssec|appsecpriv))/{regex_dname}/$", domain.siteprobeview),
    url(rf"^(domain|site)/{regex_dname}/results$", domain.resultscurrent),
    url(r"^(domain|site)/(?P<dname>.*)/(?P<id>[0-9]+)/$", domain.resultsstored, name="webtest_results"),
    # Non valid domain, convert to punycode and try again
    # these url()s should always be the last in the ^domain/ group
    url(r"^(domain|site)/(?P<dname>.*)/$", domain.validate_domain),
    url(r"^(domain|site)/(?P<dname>.*)/results$", domain.validate_domain),
    url(r"^test-mail/$", views.testmailpage),
    url(r"^mail/$", mail.index),
    url(rf"^mail/{regex_mailaddr}/$", mail.mailprocess),
    url(rf"^mail/probes/{regex_dname}/$", mail.siteprobesstatus),
    url(rf"^mail/(?P<probename>(ipv6|auth|dnssec|tls))/{regex_mailaddr}/$", mail.mailprobeview),
    url(rf"^mail/{regex_mailaddr}/results$", mail.resultscurrent),
    url(r"^mail/(?P<dname>.*)/(?P<id>[0-9]+)/$", mail.resultsstored, name="mailtest_results"),
    # Non valid mail, convert to punycode and try again
    # these url()s should always be the last in the ^mail/ group
    url(r"^mail/(?P<mailaddr>.*)/$", mail.validate_domain),
    url(r"^mail/(?P<mailaddr>.*)/results$", mail.validate_domain),
    url(rf"^clear/{regex_dname}/$", views.clear),
    url(r"^change_language/$", views.change_language, name="change_language"),
]

# Host-urls that are accessible by host-only, which should be approachable by developers as well during
# development (although your DNS is probably not set correctly to deal with the tests.
# This is not enabled by default because it returns the ip address (pii) of the requester.
if settings.DEBUG:
    urlpatterns += [
        url(r"^network_ipv4/(?P<test_id>[0-9abcdef]+)/$", views.connection.network_ipv4),
        url(r"^network_ipv6/(?P<test_id>[0-9abcdef]+)/$", views.connection.network_ipv6),
        url(r"^network_resolver/(?P<test_id>[0-9abcdef]+)/$", views.connection.network_resolver),
    ]

if hasattr(settings, "MANUAL_HOF") and settings.MANUAL_HOF:
    for key in settings.MANUAL_HOF:
        urlpatterns += [
            url(rf"^halloffame/(?P<manual_url>{key})/$", views.hofmanualpage),
        ]

if hasattr(settings, "HAS_ACCESSIBILITY_PAGE") and settings.HAS_ACCESSIBILITY_PAGE:
    urlpatterns += [
        url(r"^accessibility/$", views.accessibility),
    ]

if settings.ENABLE_BATCH is True:
    urlpatterns += [
        url(
            rf"^api/batch/v{BATCH_API_MAJOR_VERSION}/requests$",
            batch.endpoint_requests,
            name="batch_endpoint_requests",
        ),
        url(
            rf"^api/batch/v{BATCH_API_MAJOR_VERSION}/requests/{regex_testid}$",
            batch.endpoint_request,
            name="batch_endpoint_request",
        ),
        url(
            rf"^api/batch/v{BATCH_API_MAJOR_VERSION}/requests/{regex_testid}/results$",
            batch.endpoint_results,
            name="batch_endpoint_results",
        ),
        url(
            rf"^api/batch/v{BATCH_API_MAJOR_VERSION}/requests/{regex_testid}/results_technical$",
            batch.endpoint_results_technical,
            name="batch_endpoint_results_technical",
        ),
        url(
            rf"^api/batch/v{BATCH_API_MAJOR_VERSION}/metadata/report$",
            batch.endpoint_metadata_report,
            name="batch_endpoint_metadata_report",
        ),
        url(r"^api/batch/openapi.yaml$", batch.documentation, name="batch_documentation"),
        # The following should always be the last to catch now-invalid urls.
        url(r"^api/batch/", batch.old_url, name="batch_old"),
    ]


if settings.DEBUG is True:
    pass

# Static URLs, these are normally never exposed on production environment as
# they are served by the webserver upfront. Since they are not accessed, it
# does not matter to leave them in.
urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
