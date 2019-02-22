# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
import re

from django.conf import settings
from django.utils import translation
from django.utils.deprecation import MiddlewareMixin


class ActivateTranslationMiddleware(MiddlewareMixin):
    """
    This middleware activates the appropriate translation based on the
    request's hostname.

    For more information see the Installation file.

    """
    accept_language_regex = re.compile("^(?P<language>[^-;]{2,3})[^;]*"
                                       "(;q=(?P<pref>[0-9.]+))?$")

    def process_request(self, request):
        hostname = request.get_host().split(':')[0]
        current_language = hostname.split('.', 1)[0]
        if translation.check_for_language(current_language):
            request.current_language_code = current_language
        else:
            request.current_language_code = self.get_preferred_language(
                                request.META.get('HTTP_ACCEPT_LANGUAGE', ''))
        translation.activate(request.current_language_code)

    def get_preferred_language(self, http_accept_language):
        """
        Find and return the most preferred client language that is
        available. Otherwise return the default language.

        """
        preferred_languages = []
        for language in http_accept_language.split(','):
            got_match = self.accept_language_regex.match(language)
            if got_match:
                preferred_languages.append(got_match.group('language', 'pref'))
        preferred_languages = sorted(preferred_languages, reverse=True,
                                     key=lambda x: x[1] if x[1] else '1')

        prev_language = None
        for language, _ in preferred_languages:
            # In case the client's preference includes a lot of subcodes for a
            # given language code (e.g., arabic) speed up things a little.
            if language == prev_language:
                continue

            for available_language, _ in settings.LANGUAGES:
                if language.lower() == available_language:
                    return language

            prev_language = language

        return settings.LANGUAGE_CODE
