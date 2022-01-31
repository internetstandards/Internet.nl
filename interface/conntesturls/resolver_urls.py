# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
from django.conf.urls import url

from interface.views.connection import network_resolver

urlpatterns = [
    url(r"^$", network_resolver),
]
