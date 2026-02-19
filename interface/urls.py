# Copyright: 2022, ECP, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
from django.conf import settings
from django.urls import path, re_path
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
    path("", views.indexpage),
    re_path(r"^statistics/(?P<start_date>[0-9]{8})/(?P<end_date>[0-9]{8})/$", stats.statistics),
    path("copyright/", views.copyrightpage),
    path("faqs/", views.faqindexpage),
    path("faqs/report/", views.faqreport, name="faqs_report"),
    path("faqs/badges/", views.faqbadges, name="faqs_badges"),
    re_path(r"^faqs/(?P<subject>[a-zA-Z0-9\-]{1,40})/$", views.faqarticlepage),
    path("usage/", views.indexpage),
    path("widget-site/", views.widgetsitepage),
    path("widget-mail/", views.widgetmailpage),
    path("halloffame/", views.hofchampionspage),
    path("halloffame/web/", views.hofwebpage),
    path("halloffame/mail/", views.hofmailpage),
    path("test-connection/", views.testconnectionpage),
    path("connection/", connection.index),
    re_path(r"^(connection|conn)/gettestid/$", connection.gettestid),
    re_path(rf"^(connection|conn)/finished/{regex_testid}$", connection.finished),
    re_path(rf"^(connection|conn)/addr-test/{regex_testid}/$", connection.addr_ipv6),
    re_path(rf"^(connection|conn)/{regex_testid}/results$", connection.results),
    path("test-site/", views.testsitepage),
    re_path(r"^(domain|site)/$", domain.index),
    re_path(rf"^(domain|site)/{regex_dname}/$", domain.siteprocess),
    re_path(rf"^(domain|site)/probes/{regex_dname}/$", domain.siteprobesstatus),
    re_path(rf"^(domain|site)/(?P<probename>(ipv6|tls|dnssec|appsecpriv|rpki))/{regex_dname}/$", domain.siteprobeview),
    re_path(rf"^(domain|site)/{regex_dname}/results$", domain.resultscurrent),
    re_path(r"^(domain|site)/(?P<dname>.*)/(?P<id>[0-9]+)/$", domain.resultsstored, name="webtest_results"),
    # Non valid domain, convert to punycode and try again
    # these url()s should always be the last in the ^domain/ group
    re_path(r"^(domain|site)/(?P<dname>.*)/$", domain.validate_domain),
    re_path(r"^(domain|site)/(?P<dname>.*)/results$", domain.validate_domain),
    path("test-mail/", views.testmailpage),
    path("mail/", mail.index),
    re_path(rf"^mail/{regex_mailaddr}/$", mail.mailprocess),
    re_path(rf"^mail/probes/{regex_dname}/$", mail.siteprobesstatus),
    re_path(rf"^mail/(?P<probename>(ipv6|auth|dnssec|tls))/{regex_mailaddr}/$", mail.mailprobeview),
    re_path(rf"^mail/{regex_mailaddr}/results$", mail.resultscurrent),
    re_path(r"^mail/(?P<dname>.*)/(?P<id>[0-9]+)/$", mail.resultsstored, name="mailtest_results"),
    # Non valid mail, convert to punycode and try again
    # these url()s should always be the last in the ^mail/ group
    re_path(r"^mail/(?P<mailaddr>.*)/$", mail.validate_domain),
    re_path(r"^mail/(?P<mailaddr>.*)/results$", mail.validate_domain),
    re_path(rf"^clear/{regex_dname}/$", views.clear),
    path("change_language/", views.change_language, name="change_language"),
    path("contact/", views.indexpage),
    path("blogs/", views.blogindexpage),
    re_path(r"^blogs/(?P<addr>[a-zA-Z0-9\-]{1,40})/$", views.blogarticlepage),
    re_path(r"^blogs/(?P<author>[a-zA-Z0-9\-]{1,40})/(?P<article>[a-zA-Z0-9\-]{1,80})/$", views.blogarticlepage),
    path("news/", views.newsindexpage),
    re_path(r"^news/(?P<article>[a-zA-Z0-9\-]{1,80})/$", views.newsarticlepage),
    path("articles/", views.articleindexpage),
    path("article/", views.articlespage),
    re_path(r"^article/(?P<article>[a-zA-Z0-9\.\-]{1,80})/$", views.articlepage),
    path("about/", views.aboutpage),
    path("disclosure/", views.disclosurepage),
    path("privacy/", views.privacypage),
]

# Host-urls that are accessible by host-only, which should be approachable by developers as well during
# development (although your DNS is probably not set correctly to deal with the tests.
# This is not enabled by default because it returns the ip address (pii) of the requester.
if settings.DEBUG:
    urlpatterns += [
        re_path(r"^network_ipv4/(?P<test_id>[0-9abcdef]+)/$", views.connection.network_ipv4),
        re_path(r"^network_ipv6/(?P<test_id>[0-9abcdef]+)/$", views.connection.network_ipv6),
        re_path(r"^network_resolver/(?P<test_id>[0-9abcdef]+)/$", views.connection.network_resolver),
    ]

if hasattr(settings, "MANUAL_HOF") and settings.MANUAL_HOF:
    for key in settings.MANUAL_HOF:
        urlpatterns += [
            re_path(rf"^halloffame/(?P<manual_url>{key})/$", views.hofmanualpage),
        ]

if hasattr(settings, "HAS_ACCESSIBILITY_PAGE") and settings.HAS_ACCESSIBILITY_PAGE:
    urlpatterns += [
        path("accessibility/", views.accessibility),
    ]

if settings.ENABLE_BATCH is True:
    urlpatterns += [
        re_path(
            rf"^api/batch/v{BATCH_API_MAJOR_VERSION}/requests$",
            batch.endpoint_requests,
            name="batch_endpoint_requests",
        ),
        re_path(
            rf"^api/batch/v{BATCH_API_MAJOR_VERSION}/requests/{regex_testid}$",
            batch.endpoint_request,
            name="batch_endpoint_request",
        ),
        re_path(
            rf"^api/batch/v{BATCH_API_MAJOR_VERSION}/requests/{regex_testid}/results$",
            batch.endpoint_results,
            name="batch_endpoint_results",
        ),
        re_path(
            rf"^api/batch/v{BATCH_API_MAJOR_VERSION}/requests/{regex_testid}/results_technical$",
            batch.endpoint_results_technical,
            name="batch_endpoint_results_technical",
        ),
        re_path(
            rf"^api/batch/v{BATCH_API_MAJOR_VERSION}/metadata/report$",
            batch.endpoint_metadata_report,
            name="batch_endpoint_metadata_report",
        ),
        path("api/batch/openapi.yaml", batch.documentation, name="batch_documentation"),
        # The following should always be the last to catch now-invalid urls.
        re_path(r"^api/batch/", batch.old_url, name="batch_old"),
    ]

# Serve static files for development, for production `whitenoise` app is used and the webserver is
# expected to cache /static
urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
