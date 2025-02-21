# Copyright: 2022, ECP, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
from django.urls import include, path
from django.conf import settings

urlpatterns = [
    path("", include("interface.urls")),
]

if settings.AUTORELOAD:
    urlpatterns += [path("__reload__/", include("django_browser_reload.urls"))]

handler404 = "interface.views.page404"
