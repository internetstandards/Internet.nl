# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
import http.client
import socket

from .shared import NoIpError, http_fetch, MAX_REDIRECT_DEPTH
from .. import scoring


class HeaderCheckerContentEncoding(object):
    """
    Class for checking the Content-Encoding HTTP header.

    """
    def __init__(self):
        self.name = "Content-Encoding"

    def check(self, value, results):
        """
        Check if the header has any value.

        """
        if value:
            results['http_compression_enabled'] = True
            score = scoring.WEB_TLS_HTTP_COMPRESSION_BAD
            results['http_compression_score'] = score

    def get_positive_values(self):
        return {
            'http_compression_enabled': False,
            'http_compression_score': scoring.WEB_TLS_HTTP_COMPRESSION_GOOD,
        }

    def get_negative_values(self):
        return {
            'http_compression_enabled': True,
            'http_compression_score': scoring.WEB_TLS_HTTP_COMPRESSION_BAD,
        }


class HeaderCheckerContentSecurityPolicy(object):
    """
    Class for checking the Content-Security-Policy HTTP header.

    """
    def __init__(self):
        self.name = "Content-Security-Policy"

    def check(self, value, results):
        """
        Check if the header has any value.

        """
        if not value:
            results['content_security_policy_enabled'] = False
            score = scoring.WEB_APPSECPRIV_CONTENT_SECURITY_POLICY_BAD
            results['content_security_policy_score'] = score
        else:
            values = value.split(",")
            results['content_security_policy_values'].extend(values)

    def get_positive_values(self):
        score = scoring.WEB_APPSECPRIV_CONTENT_SECURITY_POLICY_GOOD
        return {
            'content_security_policy_enabled': True,
            'content_security_policy_score': score,
            'content_security_policy_values': [],
        }

    def get_negative_values(self):
        score = scoring.WEB_APPSECPRIV_CONTENT_SECURITY_POLICY_BAD
        return {
            'content_security_policy_enabled': False,
            'content_security_policy_score': score,
            'content_security_policy_values': [],
        }


class HeaderCheckerStrictTransportSecurity(object):
    """
    Class for checking the Strict-Transport-Security HTTP header.

    """
    def __init__(self):
        self.name = "Strict-Transport-Security"
        self.first_time_seen = True

    def check(self, value, results):
        """
        Check if the *first* HSTS header value is more than 6 months.

        """
        if self.first_time_seen and not value:
            results['hsts_enabled'] = False
            results['hsts_score'] = scoring.WEB_TLS_HSTS_BAD
            self.first_time_seen = False
        elif value:
            header_values = value.split(",")
            try:
                max_age = header_values[0].lower().split(
                    'max-age=')[1].split(';')[0]
                # Check if lower than 6 months.
                if self.first_time_seen and int(max_age) < 15552000:
                    results['hsts_score'] = scoring.WEB_TLS_HSTS_PARTIAL
                    self.first_time_seen = False
            except (ValueError, IndexError):
                if self.first_time_seen:
                    results['hsts_score'] = scoring.WEB_TLS_HSTS_BAD
                    results['hsts_enabled'] = False
                    self.first_time_seen = False
            results['hsts_policies'].extend(header_values)

    def get_positive_values(self):
        return {
            'hsts_enabled': True,
            'hsts_policies': [],
            'hsts_score': scoring.WEB_TLS_HSTS_GOOD,
        }

    def get_negative_values(self):
        return {
            'hsts_enabled': False,
            'hsts_policies': [],
            'hsts_score': scoring.WEB_TLS_HSTS_BAD,
        }


class HeaderCheckerXFrameOptions(object):
    """
    Class for checking the X-Frame-Options HTTP header.

    """
    def __init__(self):
        self.name = "X-Frame-Options"

    def check(self, value, results):
        """
        Check if the header has any of the allowed values.

        """
        if not value:
            score = scoring.WEB_APPSECPRIV_X_FRAME_OPTIONS_BAD
            results['x_frame_options_score'] = score
            results['x_frame_options_enabled'] = False
        else:
            values = value.split(",")
            first_header = values[0].upper()
            if not (first_header == "DENY"
                    or first_header == "SAMEORIGIN"
                    or first_header.startswith("ALLOW-FROM")):
                score = scoring.WEB_APPSECPRIV_X_FRAME_OPTIONS_BAD
                results['x_frame_options_score'] = score
                results['x_frame_options_enabled'] = False
            results['x_frame_options_values'].extend(values)

    def get_positive_values(self):
        score = scoring.WEB_APPSECPRIV_X_FRAME_OPTIONS_GOOD
        return {
            'x_frame_options_enabled': True,
            'x_frame_options_score': score,
            'x_frame_options_values': [],
        }

    def get_negative_values(self):
        score = scoring.WEB_APPSECPRIV_X_FRAME_OPTIONS_BAD
        return {
            'x_frame_options_enabled': False,
            'x_frame_options_score': score,
            'x_frame_options_values': [],
        }


class HeaderCheckerXContentTypeOptions(object):
    """
    Class for checking the X-Content-Type-Options HTTP header.

    """
    def __init__(self):
        self.name = "X-Content-Type-Options"

    def check(self, value, results):
        """
        Check if the header has the allowed value.

        """
        if not value:
            score = scoring.WEB_APPSECPRIV_X_CONTENT_TYPE_OPTIONS_BAD
            results['x_content_type_options_score'] = score
            results['x_content_type_options_enabled'] = False
        else:
            values = value.split(",")
            if not values[0].lower() == "nosniff":
                score = scoring.WEB_APPSECPRIV_X_CONTENT_TYPE_OPTIONS_BAD
                results['x_content_type_options_score'] = score
                results['x_content_type_options_enabled'] = False
            results['x_content_type_options_values'].extend(values)

    def get_positive_values(self):
        score = scoring.WEB_APPSECPRIV_X_CONTENT_TYPE_OPTIONS_GOOD
        return {
            'x_content_type_options_enabled': True,
            'x_content_type_options_score': score,
            'x_content_type_options_values': [],
        }

    def get_negative_values(self):
        score = scoring.WEB_APPSECPRIV_X_CONTENT_TYPE_OPTIONS_BAD
        return {
            'x_content_type_options_enabled': False,
            'x_content_type_options_score': score,
            'x_content_type_options_values': [],
        }


class HeaderCheckerXXssProtection(object):
    """
    Class for checking the X-Xss-Protection HTTP header.

    """
    def __init__(self):
        self.name = "X-Xss-Protection"

    def check(self, value, results):
        """
        Check if XSS protection is enabled.

        """
        if not value:
            score = scoring.WEB_APPSECPRIV_X_XSS_PROTECTION_BAD
            results['x_xss_protection_score'] = score
            results['x_xss_protection_enabled'] = False
        else:
            values = value.split(",")
            enabled = values[0].split(";")[0]
            if enabled == "0":
                score = scoring.WEB_APPSECPRIV_X_XSS_PROTECTION_BAD
                results['x_xss_protection_score'] = score
                results['x_xss_protection_enabled'] = False
            results['x_xss_protection_values'].extend(values)

    def get_positive_values(self):
        score = scoring.WEB_APPSECPRIV_X_CONTENT_TYPE_OPTIONS_GOOD
        return {
            'x_xss_protection_enabled': True,
            'x_xss_protection_score': score,
            'x_xss_protection_values': [],
        }

    def get_negative_values(self):
        score = scoring.WEB_APPSECPRIV_X_CONTENT_TYPE_OPTIONS_BAD
        return {
            'x_xss_protection_enabled': False,
            'x_xss_protection_score': score,
            'x_xss_protection_values': [],
        }


class HeaderCheckerReferrerPolicy(object):
    """
    Class for checking the Referrer-Policy HTTP header.

    """
    def __init__(self):
        self.name = "Referrer-Policy"

    def check(self, value, results):
        """
        Check if the header has any of the allowed values.

        """
        if value == "":
            # Empty string defaults to 'no-referrer-when-downgrade'.
            results['referrer_policy_values'] = ['""']

        elif not value:
            score = scoring.WEB_APPSECPRIV_REFERRER_POLICY_BAD
            results['referrer_policy_score'] = score
            results['referrer_policy_enabled'] = False

        else:
            values = value.split(",")
            for value in values:
                if value.lower() not in [
                        'no-referrer',
                        'no-referrer-when-downgrade',
                        'origin',
                        'origin-when-cross-origin',
                        'same-origin',
                        'strict-origin',
                        'strict-origin-when-cross-origin',
                        'unsafe-url',
                        ]:
                    score = scoring.WEB_APPSECPRIV_REFERRER_POLICY_BAD
                    results['referrer_policy_score'] = score
                    results['referrer_policy_enabled'] = False
            results['referrer_policy_values'].extend(values)

    def get_positive_values(self):
        score = scoring.WEB_APPSECPRIV_REFERRER_POLICY_GOOD
        return {
            'referrer_policy_enabled': True,
            'referrer_policy_score': score,
            'referrer_policy_values': [],
        }

    def get_negative_values(self):
        score = scoring.WEB_APPSECPRIV_REFERRER_POLICY_BAD
        return {
            'referrer_policy_enabled': False,
            'referrer_policy_score': score,
            'referrer_policy_values': [],
        }


def http_headers_check(addr, url, header_checkers, task):
    results = dict()
    # set defaults to positive values. Header tests return negative values if
    # a test failed.
    for h in header_checkers:
        results.update(h.get_positive_values())

    put_headers = (("Accept-Encoding", "compress, deflate, exi, gzip, "
                                       "pack200-gzip, x-compress, x-gzip"),)
    get_headers = [h.name for h in header_checkers]
    try:
        conn, res, headers, visited_hosts = http_fetch(
            url, af=addr[0], path="", port=443, task=task,
            addr=addr[1], put_headers=put_headers,
            depth=MAX_REDIRECT_DEPTH,
            needed_headers=get_headers)
    except (socket.error, http.client.BadStatusLine, NoIpError):
        # Not able to connect, return negative values
        for h in header_checkers:
            results.update(h.get_negative_values())
        results['server_reachable'] = False
    else:
        if 443 in headers:
            for name, value in headers[443]:
                for header_checker in header_checkers:
                    if name == header_checker.name:
                        header_checker.check(value, results)
                        break

    return results
