# Copyright: 2026, ECP, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
from urllib.parse import quote

from django.conf import settings
from django.contrib.staticfiles.storage import StaticFilesStorage


class ReleaseStaticFilesStorage(StaticFilesStorage):
    """Add the release to static file URLs. Browsers cache static files for a day under
    fixed names, so after a release they would otherwise mix old CSS and JS with new pages."""

    def url(self, name):
        return f"{super().url(name)}?v={quote(settings.VERSION)}"
