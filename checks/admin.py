# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
from django.contrib import admin

# Register your models here.
from checks.models import ConnectionTest


@admin.register(ConnectionTest)
class ConnectionTestAdmin(admin.ModelAdmin):

    list_display = ('id', 'ipv4_addr', 'ipv6_addr', 'ipv6_owner', 'ipv6_reverse',
                    'aaaa_ipv6', 'addr_ipv6', 'resolv_ipv6', 'score_ipv6', 'score_ipv6_max')

