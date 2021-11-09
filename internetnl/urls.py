# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
from django.conf import settings
from django.conf.urls import include, url
from django.contrib import admin

urlpatterns = [
    url(r'^', include('checks.urls')),
]
handler404 = 'checks.views.page404'

if settings.DEBUG is True:
    urlpatterns += [
        url(r'^admin/', admin.site.urls),
    ]
