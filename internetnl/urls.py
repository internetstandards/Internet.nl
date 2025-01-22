# Copyright: 2022, ECP, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
from django.urls import include, path

urlpatterns = [
    path("", include("interface.urls")),
]
handler404 = "interface.views.page404"
