# Copyright: 2022, ECP, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
from django.conf.urls import url

from interface.views.connection import network_ipv4

urlpatterns = [
    url(r"^$", network_ipv4),
]
