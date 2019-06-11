# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
import re

from ..models import BatchRequestType
from ..scoring import STATUS_SUCCESS


def get_applicable_views(user, batch_request):
    views = []
    user_views = user.custom_views.all()
    for custom_view in user_views:
        view_class = VIEWS_MAP.get(custom_view.name)
        if not view_class:
            break

        if view_class.is_applicable(batch_request):
            views.append(view_class)
    return views


def gather_views_results(views, batch_domain, batch_request_type):
    """
    Return the results for the given views.

    """
    results = []
    if not views:
        return results

    for view in views:
        result = view.get_view_data(batch_request_type, batch_domain)
        if result:
            if isinstance(result, list):
                results.extend(result)
            else:
                results.append(result)
    return results


def _camel_case_to_snake(string):
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', string)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()


class CustomView(object):
    """
    Base class for custom views.

    The `self.settings` keys dictate if the view is applicable in web and mail
    tests. Further settings per view can be defined in those keys or directly
    under `self.settings`.

    .. note:: The class name of the custom views must be CamelCase and the last
              word must be `View`. Every new custom view must have a docstring
              that will be used as description in the database.

    """
    def __init__(self):
        self.name = self._class_name_to_snake()
        self.setup()

    def setup(self):
        self.settings = {
            BatchRequestType.web: {},
            BatchRequestType.mail: {}
        }

    def is_applicable(self, batch_request):
        """
        Check if the view should be applied based on the test type.

        """
        if batch_request.type in self.settings:
            return True
        return False

    def get_view_data(self, batch_request_type, batch_domain):
        return None

    def get_group_result_from_report(self, batch_domain, batch_request_type):
        """
        Check all the report_items in the report for SUCCESS.

        """
        result = True
        batch_test = batch_domain.get_batch_test()
        report = getattr(
            batch_test.report, self.settings['report_model']).report
        report_items = self.settings[batch_request_type]['report_items']
        for report_item in report_items:
            if not report.get(report_item):
                result = False
                break
            elif report[report_item]['status'] != STATUS_SUCCESS:
                result = False
                break
        return result

    def get_raw_data_from_reports(self, batch_domain, batch_request_type):
        """
        Get the raw reports for this domain.

        .. note:: This is not a True/False view.

        """
        result = {}
        batch_test = batch_domain.get_batch_test()
        for category in self.settings[batch_request_type]['test_categories']:
            report = getattr(batch_test.report, category).report
            result[category] = report
        return result

    def _class_name_to_snake(self):
        """
        Convert the class name from camel-case to snake-case while removing
        the 'View' part.

        """
        name = self.__class__.__name__.replace("View", "")
        return _camel_case_to_snake(name)


class TlsAvailableView(CustomView):
    """
    View to check if TLS is available.

    """
    def setup(self):
        self.settings = {
            BatchRequestType.web: {
                'report_items': [
                    'https_exists',
                ]
            },
            BatchRequestType.mail: {
                'report_items': [
                    'starttls_exists',
                ]
            },
            'report_model': 'tls',
        }

    def get_view_data(self, batch_request_type, batch_domain):
        result = self.get_group_result_from_report(
            batch_domain, batch_request_type)
        return dict(name=self.name, result=result)


class TlsNcscWebView(CustomView):
    """
    View to check if TLS follows the NCSC's guidelines.

    """
    def setup(self):
        self.settings = {
            BatchRequestType.web: {
                'report_items': [
                    'https_exists',
                    'fs_params',
                    'tls_ciphers',
                    'tls_version',
                    'tls_compression',
                    'renegotiation_secure',
                    'renegotiation_client',
                    'cert_trust',
                    'cert_pubkey',
                    'cert_signature',
                    'cert_hostmatch',
                    'zero_rtt',
                    'ocsp_stapling',
                ]
            },
            'report_model': 'tls',
        }

    def get_view_data(self, batch_request_type, batch_domain):
        result = self.get_group_result_from_report(
            batch_domain, batch_request_type)
        return dict(name=self.name, result=result)


class Ipv6NameserverView(CustomView):
    """
    View to check addresses and reachability of nameservers.

    """
    def setup(self):
        self.settings = {
            BatchRequestType.web: {
                'report_items': [
                    'ns_aaaa',
                    'ns_reach',
                ]},
            BatchRequestType.mail: {
                'report_items': [
                    'ns_aaaa',
                    'ns_reach',
                ]},
            'report_model': 'ipv6',
        }

    def get_view_data(self, batch_request_type, batch_domain):
        result = self.get_group_result_from_report(
            batch_domain, batch_request_type)
        return dict(name=self.name, result=result)


class Ipv6WebserverView(CustomView):
    """
    View to check addresses, reachability and IPv4/6 difference of the
    webserver.

    """
    def setup(self):
        self.settings = {
            BatchRequestType.web: {
                'report_items': [
                    'web_aaaa',
                    'web_reach',
                    'web_ipv46',
                ]},
            'report_model': 'ipv6',
        }

    def get_view_data(self, batch_request_type, batch_domain):
        result = self.get_group_result_from_report(
            batch_domain, batch_request_type)
        return dict(name=self.name, result=result)


class Ipv6MailserverView(CustomView):
    """
    View to check addresses and reachability of mailservers.

    """
    def setup(self):
        self.settings = {
            BatchRequestType.mail: {
                'report_items': [
                    'mx_aaaa',
                    'mx_reach',
                ]},
            'report_model': 'ipv6',
        }

    def get_view_data(self, batch_request_type, batch_domain):
        result = self.get_group_result_from_report(
            batch_domain, batch_request_type)
        return dict(name=self.name, result=result)


class DnssecEmailDomainView(CustomView):
    """
    View to check the existence and validity of DNSSEC on the email address
    domain.

    """
    def setup(self):
        self.settings = {
            BatchRequestType.mail: {
                'report_items': [
                    'dnssec_exists',
                    'dnssec_valid',
                ]},
            'report_model': 'dnssec',
        }

    def get_view_data(self, batch_request_type, batch_domain):
        result = self.get_group_result_from_report(
            batch_domain, batch_request_type)
        return dict(name=self.name, result=result)


class DnssecMailserverDomainView(CustomView):
    """
    View to check the existence and validity of DNSSEC on the mailserver
    domain.

    """
    def setup(self):
        self.settings = {
            BatchRequestType.mail: {
                'report_items': [
                    'dnssec_mx_exists',
                    'dnssec_mx_valid',
                ]},
            'report_model': 'dnssec',
        }

    def get_view_data(self, batch_request_type, batch_domain):
        result = self.get_group_result_from_report(
            batch_domain, batch_request_type)
        return dict(name=self.name, result=result)


class HttpsEnforcedView(CustomView):
    """
    View to check if HTTPS enforcement is in place.

    """
    def setup(self):
        self.settings = {
            BatchRequestType.web: {
                'report_items': [
                    'https_forced',
                ]},
            'report_model': 'tls',
        }

    def get_view_data(self, batch_request_type, batch_domain):
        result = self.get_group_result_from_report(
            batch_domain, batch_request_type)
        return dict(name=self.name, result=result)


class HstsView(CustomView):
    """
    View to check if HSTS is available.

    """
    def setup(self):
        self.settings = {
            BatchRequestType.web: {
                'report_items': [
                    'https_hsts',
                ]},
            'report_model': 'tls',
        }

    def get_view_data(self, batch_request_type, batch_domain):
        result = self.get_group_result_from_report(
            batch_domain, batch_request_type)
        return dict(name=self.name, result=result)


class DaneView(CustomView):
    """
    View to check existence and validity of DANE.

    """
    def setup(self):
        self.settings = {
            BatchRequestType.web: {
                'report_items': [
                    'dane_exists',
                    'dane_valid',
                ]},
            BatchRequestType.mail: {
                'report_items': [
                    'dane_exists',
                    'dane_valid',
                ]},
            'report_model': 'tls',
        }

    def get_view_data(self, batch_request_type, batch_domain):
        result = self.get_group_result_from_report(
            batch_domain, batch_request_type)
        return dict(name=self.name, result=result)


class DmarcView(CustomView):
    """
    View to check if DMARC is available.

    """
    def setup(self):
        self.settings = {
            BatchRequestType.mail: {}
        }

    def get_view_data(self, batch_request_type, batch_domain):
        batch_test = batch_domain.get_batch_test()
        result = batch_test.auth.dmarc_available
        return dict(name=self.name, result=result)


class DkimView(CustomView):
    """
    View to check if DKIM is available.

    """
    def setup(self):
        self.settings = {
            BatchRequestType.mail: {}
        }

    def get_view_data(self, batch_request_type, batch_domain):
        batch_test = batch_domain.get_batch_test()
        result = batch_test.auth.dkim_available
        return dict(name=self.name, result=result)


class SpfView(CustomView):
    """
    View to check if SPF is available.

    """
    def setup(self):
        self.settings = {
            BatchRequestType.mail: {}
        }

    def get_view_data(self, batch_request_type, batch_domain):
        batch_test = batch_domain.get_batch_test()
        result = batch_test.auth.spf_available
        return dict(name=self.name, result=result)


class RawReportsView(CustomView):
    """
    View to return the raw data from the reports.

    """
    def setup(self):
        self.settings = {
            BatchRequestType.web: {
                'test_categories': ['ipv6', 'dnssec', 'tls']
            },
            BatchRequestType.mail: {
                'test_categories': ['ipv6', 'dnssec', 'auth', 'tls']
            }
        }

    def get_view_data(self, batch_request_type, batch_domain):
        result = self.get_raw_data_from_reports(
            batch_domain, batch_request_type)
        return dict(name=self.name, result=result)


class ForumStandaardisatieView(CustomView):
    """
    View specified by Forum Standaardisatie.
    It gets the specified results from a mail or web report and returns them
    mapped to a specified name.

    """
    def setup(self):
        self.settings = {
            BatchRequestType.web: {
                'ipv6': {
                    'ns_aaaa': 'web_ipv6_ns_address',
                    'ns_reach': 'web_ipv6_ns_reach',
                    'web_aaaa': 'web_ipv6_ws_address',
                    'web_reach': 'web_ipv6_ws_reach',
                    'web_ipv46': 'web_ipv6_ws_similar',
                },
                'dnssec': {
                    'dnssec_exists': 'web_dnssec_exist',
                    'dnssec_valid': 'web_dnssec_valid',
                },
                'tls': {
                    'https_exists': 'web_https_http_available',
                    'https_forced': 'web_https_http_redirect',
                    'https_hsts': 'web_https_http_hsts',
                    'http_compression': 'web_https_http_compress',
                    'tls_version': 'web_https_tls_version',
                    'tls_ciphers': 'web_https_tls_ciphers',
                    'fs_params': 'web_https_tls_keyexchange',
                    'tls_compression': 'web_https_tls_compress',
                    'renegotiation_secure': 'web_https_tls_secreneg',
                    'renegotiation_client': 'web_https_tls_clientreneg',
                    'cert_trust': 'web_https_cert_chain',
                    'cert_pubkey': 'web_https_cert_pubkey',
                    'cert_signature': 'web_https_cert_sig',
                    'cert_hostmatch': 'web_https_cert_domain',
                    'dane_exists': 'web_https_dane_exist',
                    'dane_valid': 'web_https_dane_valid',
                    'zero_rtt': 'web_https_tls_zero_rtt',
                    'ocsp_stapling': 'web_https_tls_ocsp_stapling',
                },
            },
            BatchRequestType.mail: {
                'ipv6': {
                    'ns_aaaa': 'mail_ipv6_ns_address',
                    'ns_reach': 'mail_ipv6_ns_reach',
                    'mx_aaaa': 'mail_ipv6_mx_address',
                    'mx_reach': 'mail_ipv6_mx_reach',
                },
                'dnssec': {
                    'dnssec_exists': 'mail_dnssec_mailto_exist',
                    'dnssec_valid': 'mail_dnssec_mailto_valid',
                    'dnssec_mx_exists': 'mail_dnssec_mx_exist',
                    'dnssec_mx_valid': 'mail_dnssec_mx_valid',
                },
                'auth': {
                    'dkim': 'mail_auth_dkim_exist',
                    'dmarc': 'mail_auth_dmarc_exist',
                    'dmarc_policy': 'mail_auth_dmarc_policy',
                    'spf': 'mail_auth_spf_exist',
                    'spf_policy': 'mail_auth_spf_policy',
                },
                'tls': {
                    'starttls_exists': 'mail_starttls_tls_available',
                    'tls_version': 'mail_starttls_tls_version',
                    'tls_ciphers': 'mail_starttls_tls_ciphers',
                    'fs_params': 'mail_starttls_tls_keyexchange',
                    'tls_compression': 'mail_starttls_tls_compress',
                    'renegotiation_secure': 'mail_starttls_tls_secreneg',
                    'renegotiation_client': 'mail_starttls_tls_clientreneg',
                    'cert_trust': 'mail_starttls_cert_chain',
                    'cert_pubkey': 'mail_starttls_cert_pubkey',
                    'cert_signature': 'mail_starttls_cert_sig',
                    'cert_hostmatch': 'mail_starttls_cert_domain',
                    'dane_exists': 'mail_starttls_dane_exist',
                    'dane_valid': 'mail_starttls_dane_valid',
                    'dane_rollover': 'mail_starttls_dane_rollover',
                },
            },
        }

    def get_view_data(self, batch_request_type, batch_domain):
        """
        For each test item specified in the settings above check if the test
        passed and return the result based on the name mapping provided in the
        settings above.

        """
        view_data = []
        batch_test = batch_domain.get_batch_test()
        for report_model, name_mappings in self.settings[batch_request_type].items():
            report = getattr(batch_test.report, report_model).report
            for item, data in report.items():
                if name_mappings.get(item):
                    view_data.append(dict(
                        name=name_mappings[item],
                        result=data['status'] == STATUS_SUCCESS))
        return view_data


def _create_views_map(view_instances):
    views_map = dict()
    for view in view_instances:
        name = _camel_case_to_snake(view.__class__.__name__)
        views_map[name] = view
    return views_map


VIEWS_MAP = _create_views_map([
    TlsAvailableView(),
    TlsNcscWebView(),
    DmarcView(),
    DkimView(),
    SpfView(),
    Ipv6NameserverView(),
    Ipv6WebserverView(),
    Ipv6MailserverView(),
    DnssecEmailDomainView(),
    DnssecMailserverDomainView(),
    DaneView(),
    HttpsEnforcedView(),
    HstsView(),
    RawReportsView(),
    ForumStandaardisatieView(),
])
