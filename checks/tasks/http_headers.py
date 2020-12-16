# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
from collections import namedtuple, defaultdict
import http.client
import re
import socket

from .tls_connection import NoIpError, http_fetch, MAX_REDIRECT_DEPTH
from .tls_connection import ConnectionSocketException
from .tls_connection import ConnectionHandshakeException
from .. import scoring


def get_multiple_values_from_header(header):
    """
    Get all the values for the header.

    Multiple values of the same header are in a comma separated list; make sure
    to ignore white space when splitting the values.

    """
    return [value.strip() for value in header.split(',')]


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
    Directive = namedtuple('Directive', [
        'default', 'values', 'values_optional', 'values_regex_all'],
        defaults=[[], [], False, False])
    host_source_regex = re.compile(
        r'(?P<scheme>[^:]+://)?(?P<host>[^:]+\.[^:]+)(:(?P<port>\d+))?')
    scheme_source_regex = re.compile(
        r'(?:https?|data|mediastream|blob|filesystem):')
    self_none_regex = re.compile(r"(?:'self'|'none')")
    other_source_regex = re.compile(
        r"(?:"
        r"'self'|'unsafe-eval'|'unsafe-hashes'|'unsafe-inline'|'none'"
        r"|'nonce-[+a-zA-Z0-9/]+=*'"
        r"|'(?:sha256|sha384|sha512)-[+a-zA-Z0-9/]+=*')")
    strict_dynamic_regex = re.compile(r"'strict-dynamic'")
    report_sample_regex = re.compile(r"'report-sample'")
    plugin_types_regex = re.compile(r'[^/]+/[^/]+')
    sandox_values_regex = re.compile(
        r'(?:allow-downloads-without-user-activation|allow-forms|allow-modals'
        r'|allow-orientation-lock|allow-pointer-lock|allow-popups'
        r'|allow-popups-to-escape-sandbox|allow-presentation|allow-same-origin'
        r'|allow-scripts|allow-storage-access-by-user-activation'
        r'|allow-top-navigation|allow-top-navigation-by-user-activation)')
    directives = {
        'child-src': Directive(
            default=['default-src'],
            values=[
                host_source_regex, scheme_source_regex, other_source_regex]
        ),
        'connect-src': Directive(
            default=['default-src'],
            values=[
                host_source_regex, scheme_source_regex, other_source_regex],
        ),
        'default-src': Directive(
            values=[
                host_source_regex, scheme_source_regex, other_source_regex,
                strict_dynamic_regex, report_sample_regex],
        ),
        'font-src': Directive(
            default=['default-src'],
            values=[
                host_source_regex, scheme_source_regex, other_source_regex],
        ),
        'frame-src': Directive(
            default=['child-src', 'default-src'],
            values=[
                host_source_regex, scheme_source_regex, other_source_regex],
        ),
        'img-src': Directive(
            default=['default-src'],
            values=[
                host_source_regex, scheme_source_regex, other_source_regex,
                strict_dynamic_regex, report_sample_regex],
        ),
        'manifest-src': Directive(
            default=['default-src'],
            values=[
                host_source_regex, scheme_source_regex, other_source_regex],
        ),
        'media-src': Directive(
            default=['default-src'],
            values=[
                host_source_regex, scheme_source_regex, other_source_regex],
        ),
        'object-src': Directive(
            default=['default-src'],
            values=[
                host_source_regex, scheme_source_regex, other_source_regex],
        ),
        'prefetch-src': Directive(
            default=['default-src'],
            values=[
                host_source_regex, scheme_source_regex, other_source_regex],
        ),
        'script-src': Directive(
            default=['default-src'],
            values=[
                host_source_regex, scheme_source_regex, other_source_regex,
                strict_dynamic_regex, report_sample_regex],
        ),
        'script-src-elem': Directive(
            default=['script-src', 'default-src'],
            values=[
                host_source_regex, scheme_source_regex, other_source_regex,
                strict_dynamic_regex, report_sample_regex],
        ),
        'script-src-attr': Directive(
            default=['script-src', 'default-src'],
            values=[
                host_source_regex, scheme_source_regex, other_source_regex,
                strict_dynamic_regex, report_sample_regex],
        ),
        'style-src': Directive(
            default=['default-src'],
            values=[
                host_source_regex, scheme_source_regex, other_source_regex],
        ),
        'style-src-elem': Directive(
            default=['style-src', 'default-src'],
            values=[
                host_source_regex, scheme_source_regex, other_source_regex,
                report_sample_regex],
        ),
        'style-src-attr': Directive(
            default=['style-src', 'default-src'],
            values=[
                host_source_regex, scheme_source_regex, other_source_regex,
                report_sample_regex],
        ),
        'worker-src': Directive(
            default=['child-src', 'script-src', 'default-src'],
            values=[
                host_source_regex, scheme_source_regex, other_source_regex],
        ),
        'base-uri': Directive(
            values=[
                host_source_regex, scheme_source_regex, other_source_regex,
                strict_dynamic_regex, report_sample_regex],
        ),
        'plugin-types': Directive(
            values=[plugin_types_regex],
        ),
        'sandbox': Directive(
            values=[sandox_values_regex],
            values_optional=True,
        ),
        'form-action': Directive(
            values=[
                host_source_regex, scheme_source_regex, other_source_regex,
                strict_dynamic_regex, report_sample_regex],
        ),
        'frame-ancestors': Directive(
            values=[self_none_regex],
        ),
        'navigate-to': Directive(
            values=[
                host_source_regex, scheme_source_regex, other_source_regex,
                strict_dynamic_regex, report_sample_regex],
        ),
        'report-to': Directive(
            # It could be anything in the Report-To header.
            values=[re.compile(r'.+')],
        ),
        'block-all-mixed-content': Directive(
        ),
        'trusted-types': Directive(
            values=[re.compile(
                r"^(?:'none'|"
                r"(?:\*|[\w\-#=\/@.%]+)"
                r"(?:(?: (?:\*|[\w\-#=\/@.%]+))+"
                r"(?: 'allow-duplicates')?)?)$")],
            values_optional=True,
            values_regex_all=True,
        ),
        'upgrade-insecure-requests': Directive(),
    }

    def __init__(self):
        self.name = "Content-Security-Policy"

    def _check_parsed_for_self_or_none(self, name):
        found = False
        if name in self.parsed:
            if "'self'" in self.parsed[name] or "'none'" in self.parsed[name]:
                found = True
        else:
            for parent in self.directives[name].default:
                found = self._check_parsed_for_self_or_none(parent)
                if found:
                    break
        return found

    def check(self, value, results):
        """
        Check if the header respects the following:
            - No `unsafe-inline`;
            - No `unsafe-eval`;
            - `default-src`, `frame-src` and `frame-ancestors` need to defined
              and be `'self'` or `'none'`;
            - `http:` should not be used as a scheme.

        """
        if not value:
            results['content_security_policy_enabled'] = False
            score = scoring.WEB_APPSECPRIV_CONTENT_SECURITY_POLICY_BAD
            results['content_security_policy_score'] = score
        else:
            values = get_multiple_values_from_header(value)
            results['content_security_policy_values'].extend(values)

            self.parsed = defaultdict(list)
            has_unsafe_inline = False
            has_unsafe_eval = False
            has_http = False
            has_default_src = False
            has_frame_src = False
            has_frame_ancestors = False

            for header in values:
                dirs = filter(None, header.split(';'))
                for content in dirs:
                    content = content.strip().split()
                    dir = content[0]
                    values = content[1:]
                    # Only care for known directives.
                    if dir in self.directives:
                        if (not values and self.directives[dir].values
                                and not self.directives[dir].values_optional):
                            continue

                        if self.directives[dir].values_regex_all:
                            matched = min(1, len(values))
                            test_values = [' '.join(values)]
                        else:
                            matched = len(values)
                            test_values = values

                        for value in test_values:
                            for exp_value in self.directives[dir].values:
                                if exp_value.match(value):
                                    if (not has_http and exp_value in (
                                            self.host_source_regex,
                                            self.scheme_source_regex)):
                                        if 'http:' in value:
                                            has_http = True
                                    if (not has_unsafe_inline
                                            and 'unsafe-inline' in value):
                                        has_unsafe_inline = True
                                    if (not has_unsafe_eval
                                            and 'unsafe-eval' in value):
                                        has_unsafe_eval = True
                                    matched -= 1
                                    break
                        if matched <= 0:
                            self.parsed[dir].extend(values)

            has_default_src = self._check_parsed_for_self_or_none(
                'default-src')
            has_frame_src = self._check_parsed_for_self_or_none(
                'frame-src')
            has_frame_ancestors = self._check_parsed_for_self_or_none(
                'frame-ancestors')

            if (has_unsafe_inline or has_unsafe_eval or has_http or not (
                    has_default_src and has_frame_src
                    and has_frame_ancestors)):
                results['content_security_policy_enabled'] = False
                score = scoring.WEB_APPSECPRIV_CONTENT_SECURITY_POLICY_BAD
                results['content_security_policy_score'] = score

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
        self.min_allowed = 31536000  # 1 year

    def check(self, value, results):
        """
        Check if the *first* HSTS header value is more than 6 months.

        """
        if self.first_time_seen and not value:
            results['hsts_enabled'] = False
            results['hsts_score'] = scoring.WEB_TLS_HSTS_BAD
            self.first_time_seen = False
        elif value:
            header_values = get_multiple_values_from_header(value)
            try:
                max_age = header_values[0].lower().split(
                    'max-age=')[1].split(';')[0]
                if self.first_time_seen and int(max_age) < self.min_allowed:
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
            values = get_multiple_values_from_header(value)
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
            values = get_multiple_values_from_header(value)
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
            values = get_multiple_values_from_header(value)
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
            values = get_multiple_values_from_header(value)
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


def http_headers_check(af_ip_pair, url, header_checkers, task):
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
            url, af=af_ip_pair[0], path="", port=443, task=task,
            ip_address=af_ip_pair[1], put_headers=put_headers,
            depth=MAX_REDIRECT_DEPTH,
            needed_headers=get_headers)
    except (socket.error, http.client.BadStatusLine, NoIpError,
            ConnectionHandshakeException, ConnectionSocketException):
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
