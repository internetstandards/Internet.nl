# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
from django.contrib import admin

from checks.models import (
    ASRecord,
    AutoConf,
    BatchDomain,
    BatchMailTest,
    BatchRequest,
    BatchUser,
    BatchWebTest,
    ConnectionTest,
    DomainTestAppsecpriv,
    DomainTestDnssec,
    DomainTestIpv6,
    DomainTestReport,
    DomainTestTls,
    MailTestAuth,
    MailTestDnssec,
    MailTestIpv6,
    MailTestReport,
    MailTestTls,
    MxDomain,
    NsDomain,
    Resolver,
    WebDomain,
    WebTestAppsecpriv,
)

admin.site.register(ConnectionTest)
admin.site.register(Resolver)
admin.site.register(ASRecord)
admin.site.register(DomainTestIpv6)
admin.site.register(WebDomain)
admin.site.register(MailTestTls)
admin.site.register(MailTestDnssec)
admin.site.register(DomainTestDnssec)
admin.site.register(DomainTestTls)
admin.site.register(WebTestAppsecpriv)
admin.site.register(DomainTestAppsecpriv)
admin.site.register(DomainTestReport)
admin.site.register(MailTestIpv6)
admin.site.register(NsDomain)
admin.site.register(MxDomain)
admin.site.register(MailTestAuth)
admin.site.register(MailTestReport)
admin.site.register(BatchUser)
admin.site.register(BatchRequest)
admin.site.register(BatchDomain)
admin.site.register(BatchWebTest)
admin.site.register(BatchMailTest)
admin.site.register(AutoConf)
