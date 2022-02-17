# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
from django.contrib import admin

from checks import models

admin.site.register(models.ConnectionTest)
admin.site.register(models.Resolver)
admin.site.register(models.ASRecord)

admin.site.register(models.WebDomain)
admin.site.register(models.MailTestTls)
admin.site.register(models.MailTestDnssec)
admin.site.register(models.DomainTestDnssec)
admin.site.register(models.DomainTestTls)
admin.site.register(models.WebTestAppsecpriv)
admin.site.register(models.DomainTestAppsecpriv)
admin.site.register(models.DomainTestReport)
admin.site.register(models.NsDomain)
admin.site.register(models.MxDomain)
admin.site.register(models.MailTestAuth)
admin.site.register(models.MailTestReport)
admin.site.register(models.BatchUser)
admin.site.register(models.BatchRequest)
admin.site.register(models.BatchDomain)
admin.site.register(models.BatchWebTest)
admin.site.register(models.BatchMailTest)
admin.site.register(models.AutoConf)


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


@admin.register(models.MailTestIpv6)
class MailTestIpv6(admin.ModelAdmin):
    list_display = ["timestamp", "domain", "report", "mx_score", "ns_score", "score", "max_score", "mx_status"]
    search_fields = ["domain", "report"]
    list_filter = ["timestamp"]
