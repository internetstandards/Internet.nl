# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
from django.conf.urls import url

from interface import views

urlpatterns = [
    url(r"^$", views.connection.aaaa_ipv6),
]
