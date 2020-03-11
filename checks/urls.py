# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
from django.conf.urls import url
from django.conf.urls.static import static
from django.conf import settings

from checks import views
from checks.batch import BATCH_API_VERSION
from checks.batch import views as batch
from checks.views import connection
from checks.views import domain
from checks.views import mail
from checks.views import stats


regex_tld = r'(?:[a-zA-Z]{2,63}|xn--[a-zA-Z0-9]+)'
regex_dname = r'(?P<dname>([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+' + regex_tld + ')'
regex_testid = r'(?P<testid>[a-zA-Z0-9]{1,35})'
regex_mailaddr = r'(?P<mailaddr>([a-zA-Z0-9]{0,61}@)?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+' + regex_tld + ')'

urlpatterns = [
    url(r'^$', views.indexpage),
    url(r'^statistics/(?P<start_date>[0-9]{8})/(?P<end_date>[0-9]{8})/$', stats.statistics),
    url(r'^disclosure/$', views.disclosurepage),
    url(r'^contact/$', views.indexpage),
    url(r'^copyright/$', views.copyrightpage),
    url(r'^privacy/$', views.privacypage),
    url(r'^faqs/$', views.faqindexpage),
    url(r'^faqs/report/$', views.faqreport, name="faqs_report"),
    url(r'^faqs/(?P<subject>[a-zA-Z0-9\-]{1,40})/$', views.faqarticlepage),
    url(r'^usage/$', views.indexpage),
    url(r'^about/$', views.aboutpage),
    url(r'^widget-site/$', views.widgetsitepage),
    url(r'^widget-mail/$', views.widgetmailpage),
    url(r'^partners/$', views.partnerspage),
    url(r'^blogs/$', views.blogindexpage),
    url(r'^blogs/(?P<addr>[a-zA-Z0-9\-]{1,40})/$', views.blogarticlepage),
    url(r'^blogs/(?P<author>[a-zA-Z0-9\-]{1,40})/(?P<article>[a-zA-Z0-9\-]{1,80})/$', views.blogarticlepage),
    url(r'^news/$', views.newsindexpage),
    url(r'^news/(?P<article>[a-zA-Z0-9\-]{1,80})/$', views.newsarticlepage),
    url(r'^articles/$', views.articleindexpage),
    url(r'^article/$', views.articlespage),
    url(r'^article/(?P<article>[a-zA-Z0-9\-]{1,80})/$', views.articlepage),
    url(r'^halloffame/$', views.hofchampionspage),
    url(r'^halloffame/web/$', views.hofwebpage),
    url(r'^halloffame/mail/$', views.hofmailpage),

    url(r'^test-connection/$', views.testconnectionpage),
    url(r'^connection/$', connection.index),
    url(r'^(connection|conn)/gettestid/$', connection.gettestid),
    url(r'^(connection|conn)/finished/{}$'.format(regex_testid), connection.finished),
    url(r'^(connection|conn)/addr-test/{}/$'.format(regex_testid), connection.addr_ipv6),
    url(r'^(connection|conn)/{}/results$'.format(regex_testid), connection.results),

    url(r'^test-site/$', views.testsitepage),
    url(r'^(domain|site)/$', domain.index),
    url(r'^(domain|site)/{}/$'.format(regex_dname), domain.siteprocess),
    url(r'^(domain|site)/probes/{}/$'.format(regex_dname), domain.siteprobesstatus),
    url(r'^(domain|site)/(?P<probename>(ipv6|tls|dnssec|appsecpriv))/{}/$'.format(regex_dname), domain.siteprobeview),
    url(r'^(domain|site)/{}/results$'.format(regex_dname), domain.resultscurrent),
    url(r'^(domain|site)/(?P<dname>.*)/(?P<id>[0-9]+)/$', domain.resultsstored, name='webtest_results'),
    # Non valid domain, convert to punycode and try again
    # these url()s should always be the last in the ^domain/ group
    url(r'^(domain|site)/(?P<dname>.*)/$', domain.validate_domain),
    url(r'^(domain|site)/(?P<dname>.*)/results$', domain.validate_domain),

    url(r'^test-mail/$', views.testmailpage),
    url(r'^mail/$', mail.index),
    url(r'^mail/{}/$'.format(regex_mailaddr), mail.mailprocess),
    url(r'^mail/probes/{}/$'.format(regex_dname), mail.siteprobesstatus),
    url(r'^mail/(?P<probename>(ipv6|auth|dnssec|tls))/{}/$'.format(regex_mailaddr), mail.mailprobeview),
    url(r'^mail/{}/results$'.format(regex_mailaddr), mail.resultscurrent),
    url(r'^mail/(?P<dname>.*)/(?P<id>[0-9]+)/$', mail.resultsstored, name='mailtest_results'),
    # Non valid mail, convert to punycode and try again
    # these url()s should always be the last in the ^mail/ group
    url(r'^mail/(?P<mailaddr>.*)/$', mail.validate_domain),
    url(r'^mail/(?P<mailaddr>.*)/results$', mail.validate_domain),

    url(r'^clear/{}/$'.format(regex_dname), views.clear),
    url(r'^change_language/$', views.change_language, name='change_language'),
]


if settings.ENABLE_BATCH is True:
    urlpatterns += [
        url(r'^api/batch/v{}/web/$'.format(BATCH_API_VERSION), batch.register_web_test, name='batch_web_test'),
        url(r'^api/batch/v{}/mail/$'.format(BATCH_API_VERSION), batch.register_mail_test, name='batch_email_test'),
        url(r'^api/batch/v{}/results/{}/$'.format(BATCH_API_VERSION, regex_testid), batch.get_results, name='batch_results'),
        url(r'^api/batch/v{}/list/$'.format(BATCH_API_VERSION), batch.list_tests, name='batch_list'),
        url(r'^api/batch/v{}/cancel/{}/$'.format(BATCH_API_VERSION, regex_testid), batch.cancel_test, name='batch_cancel'),
        url(r'^api/batch/documentation/?$', batch.documentation, name='batch_documentation'),
        url(r'^api/batch/verdicts/?$', batch.verdicts, name='batch_verdicts'),
        # The following should always be the last to catch now-invalid urls.
        url(r'^api/batch/', batch.old_url, name='batch_old'),
    ]


if settings.DEBUG is True:
    pass

# Static URLs, these are normally never exposed on production environment as
# they are served by the webserver upfront. Since they are not accessed, it
# does not matter to leave them in.
urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
