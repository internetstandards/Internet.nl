# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
from django.contrib import admin

from checks import models

# Bare bone admin interface:
generic_models = [
    models.ConnectionTest,
    models.Resolver,
    models.ASRecord,
    models.WebDomain,
    models.MailTestTls,
    models.MailTestDnssec,
    models.DomainTestDnssec,
    models.DomainTestTls,
    models.WebTestAppsecpriv,
    models.DomainTestAppsecpriv,
    models.NsDomain,
    models.MxDomain,
    models.MailTestAuth,
    models.MailTestReport,
    models.BatchUser,
    models.BatchRequest,
    models.BatchDomain,
    models.BatchWebTest,
    models.BatchMailTest,
    models.AutoConf,
]

for my_model in generic_models:
    admin.site.register(my_model)


class NsDomainInline(admin.TabularInline):
    model = models.NsDomain
    fields = ["domain", "v6_good", "v6_bad", "v4_good", "v4_bad", "score"]
    readonly_fields = ["domain", "v6_good", "v6_bad", "v4_good", "v4_bad", "score"]


class MxDomainInline(admin.TabularInline):
    model = models.MxDomain
    fields = ["domain", "v6_good", "v6_bad", "v4_good", "v4_bad", "score"]
    readonly_fields = ["domain", "v6_good", "v6_bad", "v4_good", "v4_bad", "score"]


class WebDomainInline(admin.TabularInline):
    model = models.WebDomain
    fields = ["domain", "v6_good", "v6_bad", "v4_good", "v4_bad", "score"]
    readonly_fields = ["domain", "v6_good", "v6_bad", "v4_good", "v4_bad", "score"]


class BatchWebTestInline(admin.TabularInline):
    model = models.BatchWebTest
    readonly_fields = [
        "report",
        "ipv6",
        "ipv6_status",
        "ipv6_errors",
        "dnssec",
        "dnssec_status",
        "dnssec_errors",
        "tls",
        "tls_status",
        "tls_errors",
        "appsecpriv",
        "appsecpriv_status",
        "appsecpriv_errors",
    ]


class DomainTestReportInline(admin.TabularInline):
    model = models.DomainTestReport
    readonly_fields = [
        "timestamp",
        "domain",
        "registrar",
        "score",
        "ipv6",
        "dnssec",
        "tls",
        "appsecpriv",
    ]


@admin.register(models.DomainTestIpv6)
class DomainTestIpv6Admin(admin.ModelAdmin):
    list_display = [
        "timestamp",
        "domain",
        "report",
        "web_simhash_distance",
        "web_simhash_score",
        "web_score",
        "mx_score",
        "ns_score",
        "score",
        "max_score",
    ]
    search_fields = ["domain", "report"]
    list_filter = ["timestamp"]

    inlines = [NsDomainInline, WebDomainInline, BatchWebTestInline, DomainTestReportInline]


@admin.register(models.MailTestIpv6)
class MailTestIpv6(admin.ModelAdmin):
    list_display = ["timestamp", "domain", "report", "mx_score", "ns_score", "score", "max_score", "mx_status"]
    search_fields = ["domain", "report"]
    list_filter = ["timestamp"]

    inlines = [NsDomainInline, MxDomainInline]


@admin.register(models.DomainTestReport)
class DomainTestReportAdmin(admin.ModelAdmin):
    list_display = ["timestamp", "domain", "registrar", "score", "ipv6", "dnssec", "tls", "appsecpriv"]

    readonly_fields = ["timestamp", "domain", "registrar", "score", "ipv6", "dnssec", "tls", "appsecpriv"]
    search_fields = ["domain"]
    list_filter = ["timestamp"]
