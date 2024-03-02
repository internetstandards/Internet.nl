# Copyright: 2022, ECP, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
from django.conf import settings
from django.urls import include, path, re_path
from django.contrib import admin

urlpatterns = [
    path("", include("interface.urls")),
]
handler404 = "interface.views.page404"

if settings.DEBUG is True:
    urlpatterns += [
        re_path(r"^admin/", admin.site.urls),
    ]
