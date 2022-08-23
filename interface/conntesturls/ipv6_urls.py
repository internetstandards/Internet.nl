# Copyright: 2022, ECP, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
from django.conf.urls import url

from interface.views.connection import aaaa_ipv6

urlpatterns = [
    url(r"^$", aaaa_ipv6),
]
