# Copyright: 2022, ECP, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
from django.conf import settings

BATCH_API_MAJOR_VERSION = "2"
BATCH_API_MINOR_VERSION = "1"
BATCH_API_PATCH_VERSION = "0"
BATCH_API_FULL_VERSION = f"{BATCH_API_MAJOR_VERSION}" f".{BATCH_API_MINOR_VERSION}" f".{BATCH_API_PATCH_VERSION}"

BATCH_INDEXES = [
    # (db_table, field_to_index, index_name),
    ("checks_domaintestdnssec", "domain", "checks_domaintestdnssec_domain"),
    ("checks_domaintestipv6", "domain", "checks_domaintestipv6_domain"),
    ("checks_mailtestauth", "domain", "checks_mailtestauth_domain"),
    ("checks_mailtestdnssec", "domain", "checks_mailtestdnssec_domain"),
    ("checks_mailtestipv6", "domain", "checks_mailtestipv6_domain"),
    ("checks_mailtesttls", "domain", "checks_mailtesttls_domain"),
    ("checks_mailtestrpki", "domain", "checks_mailtestrpki_domain"),
    ("checks_webtesttls", "domain", "checks_webtesttls_domain"),
    ("checks_webtestrpki", "domain", "checks_webtestrpki_domain"),
    ("checks_webtestappsecpriv", "domain", "checks_webtestappsecpriv_domain"),
]

BATCH_PROBE_NAME_TO_API_CATEGORY = {
    "siteipv6": "web_ipv6",
    "sitednssec": "web_dnssec",
    "sitetls": "web_https",
    "siteappsecpriv": "web_appsecpriv",
    "siterpki": "web_rpki",
    "mailipv6": "mail_ipv6",
    "maildnssec": "mail_dnssec",
    "mailauth": "mail_auth",
    "mailtls": "mail_starttls",
    "mailrpki": "mail_rpki",
}
BATCH_API_CATEGORY_TO_PROBE_NAME = {
    "web_ipv6": "ipv6",
    "web_dnssec": "dnssec",
    "web_https": "tls",
    "web_appsecpriv": "appsecpriv",
    "web_rpki": "rpki",
    "mail_ipv6": "ipv6",
    "mail_dnssec": "dnssec",
    "mail_auth": "auth",
    "mail_starttls": "tls",
    "mail_rpki": "rpki",
}

REPORT_METADATA_WEB_MAP = []


if settings.INTERNET_NL_CHECK_SUPPORT_IPV6:
    REPORT_METADATA_WEB_MAP.append(
        {
            "name": "web_ipv6",
            "type": "category",
            "translation_key": "siteipv6",
            "children": [
                {
                    "name": "web_ipv6_nameservers",
                    "type": "section",
                    "translation_key": "domain-mail ipv6 name-servers",
                    "children": [
                        {
                            "name": "web_ipv6_ns_address",
                            "name_on_report": "ns_aaaa",
                            "type": "test",
                            "translation_key": "web-mail ipv6 ns-AAAA",
                        },
                        {
                            "name": "web_ipv6_ns_reach",
                            "name_on_report": "ns_reach",
                            "type": "test",
                            "translation_key": "web-mail ipv6 ns-reach",
                        },
                    ],
                },
                {
                    "name": "web_ipv6_webserver",
                    "type": "section",
                    "translation_key": "domain ipv6 web-server",
                    "children": [
                        {
                            "name": "web_ipv6_ws_address",
                            "name_on_report": "web_aaaa",
                            "type": "test",
                            "translation_key": "web ipv6 web-AAAA",
                        },
                        {
                            "name": "web_ipv6_ws_reach",
                            "name_on_report": "web_reach",
                            "type": "test",
                            "translation_key": "web ipv6 web-reach",
                        },
                        {
                            "name": "web_ipv6_ws_similar",
                            "name_on_report": "web_ipv46",
                            "type": "test",
                            "translation_key": "web ipv6 web-ipv46",
                        },
                    ],
                },
            ],
        }
    )

if settings.INTERNET_NL_CHECK_SUPPORT_DNSSEC:
    REPORT_METADATA_WEB_MAP.append(
        {
            "name": "web_dnssec",
            "type": "category",
            "translation_key": "sitednssec",
            "children": [
                {
                    "name": "web_dnssec_exist",
                    "name_on_report": "dnssec_exists",
                    "type": "test",
                    "translation_key": "web dnnsec exists",
                },
                {
                    "name": "web_dnssec_valid",
                    "name_on_report": "dnssec_valid",
                    "type": "test",
                    "translation_key": "web dnnsec valid",
                },
            ],
        }
    )

if settings.INTERNET_NL_CHECK_SUPPORT_TLS:
    REPORT_METADATA_WEB_MAP.append(
        {
            "name": "web_https",
            "type": "category",
            "translation_key": "sitetls",
            "children": [
                {
                    "name": "web_https_http",
                    "type": "section",
                    "translation_key": "domain tls https",
                    "children": [
                        {
                            "name": "web_https_http_available",
                            "name_on_report": "https_exists",
                            "type": "test",
                            "translation_key": "web tls https-exists",
                        },
                        {
                            "name": "web_https_http_redirect",
                            "name_on_report": "https_forced",
                            "type": "test",
                            "translation_key": "web tls https-forced",
                        },
                        {
                            "name": "web_https_http_compress",
                            "name_on_report": "http_compression",
                            "type": "test",
                            "translation_key": "web tls http-compression",
                        },
                        {
                            "name": "web_https_http_hsts",
                            "name_on_report": "https_hsts",
                            "type": "test",
                            "translation_key": "web tls https-hsts",
                        },
                    ],
                },
                {
                    "name": "web_https_tls",
                    "type": "section",
                    "translation_key": "domain tls tls",
                    "children": [
                        {
                            "name": "web_https_tls_version",
                            "name_on_report": "tls_version",
                            "type": "test",
                            "translation_key": "web tls version",
                        },
                        {
                            "name": "web_https_tls_ciphers",
                            "name_on_report": "tls_ciphers",
                            "type": "test",
                            "translation_key": "web tls ciphers",
                        },
                        {
                            "name": "web_https_tls_cipherorder",
                            "name_on_report": "tls_cipher_order",
                            "type": "test",
                            "translation_key": "web tls cipher-order",
                        },
                        {
                            "name": "web_https_tls_keyexchange",
                            "name_on_report": "fs_params",
                            "type": "test",
                            "translation_key": "web tls fs-params",
                        },
                        {
                            "name": "web_https_tls_keyexchangehash",
                            "name_on_report": "kex_hash_func",
                            "type": "test",
                            "translation_key": "web tls kex-hash-func",
                        },
                        {
                            "name": "web_https_tls_compress",
                            "name_on_report": "tls_compression",
                            "type": "test",
                            "translation_key": "web tls compression",
                        },
                        {
                            "name": "web_https_tls_secreneg",
                            "name_on_report": "renegotiation_secure",
                            "type": "test",
                            "translation_key": "web tls renegotiation-secure",
                        },
                        {
                            "name": "web_https_tls_clientreneg",
                            "name_on_report": "renegotiation_client",
                            "type": "test",
                            "translation_key": "web tls renegotiation-client",
                        },
                        {
                            "name": "web_https_tls_0rtt",
                            "name_on_report": "zero_rtt",
                            "type": "test",
                            "translation_key": "web tls zero-rtt",
                        },
                        {
                            "name": "web_https_tls_ocsp",
                            "name_on_report": "ocsp_stapling",
                            "type": "test",
                            "translation_key": "web tls ocsp-stapling",
                        },
                    ],
                },
                {
                    "name": "web_https_certificate",
                    "type": "section",
                    "translation_key": "domain-mail tls certificate",
                    "children": [
                        {
                            "name": "web_https_cert_chain",
                            "name_on_report": "cert_trust",
                            "type": "test",
                            "translation_key": "web tls cert-trust",
                        },
                        {
                            "name": "web_https_cert_pubkey",
                            "name_on_report": "cert_pubkey",
                            "type": "test",
                            "translation_key": "web tls cert-pubkey",
                        },
                        {
                            "name": "web_https_cert_sig",
                            "name_on_report": "cert_signature",
                            "type": "test",
                            "translation_key": "web tls cert-signature",
                        },
                        {
                            "name": "web_https_cert_domain",
                            "name_on_report": "cert_hostmatch",
                            "type": "test",
                            "translation_key": "web tls cert-hostmatch",
                        },
                    ],
                },
                {
                    "name": "web_https_dane",
                    "type": "section",
                    "translation_key": "domain-mail tls dane",
                    "children": [
                        {
                            "name": "web_https_dane_exist",
                            "name_on_report": "dane_exists",
                            "type": "test",
                            "translation_key": "web tls dane-exists",
                        },
                        {
                            "name": "web_https_dane_valid",
                            "name_on_report": "dane_valid",
                            "type": "test",
                            "translation_key": "web tls dane-valid",
                        },
                    ],
                },
            ],
        }
    )

if settings.INTERNET_NL_CHECK_SUPPORT_APPSECPRIV:
    REPORT_METADATA_WEB_MAP.append(
        {
            "name": "web_appsecpriv",
            "type": "category",
            "translation_key": "siteappsecpriv",
            "children": [
                {
                    "name": "web_appsecpriv_http_headers",
                    "type": "section",
                    "translation_key": "domain appsecpriv http-headers",
                    "children": [
                        {
                            "name": "web_appsecpriv_x_frame_options",
                            "name_on_report": "http_x_frame",
                            "type": "test",
                            "translation_key": "web appsecpriv http-x-frame",
                        },
                        {
                            "name": "web_appsecpriv_x_content_type_options",
                            "name_on_report": "http_x_content_type",
                            "type": "test",
                            "translation_key": "web appsecpriv http-x-content",
                        },
                        {
                            "name": "web_appsecpriv_csp",
                            "name_on_report": "http_csp",
                            "type": "test",
                            "translation_key": "web appsecpriv http-csp",
                        },
                        {
                            "name": "web_appsecpriv_referrer_policy",
                            "name_on_report": "http_referrer_policy",
                            "type": "test",
                            "translation_key": "web appsecpriv http-referrer-policy",
                        },
                        {
                            "name": "web_appsecpriv_securitytxt",
                            "name_on_report": "securitytxt",
                            "type": "test",
                            "translation_key": "web appsecpriv http-securitytxt",
                        },
                    ],
                }
            ],
        }
    )

if settings.INTERNET_NL_CHECK_SUPPORT_RPKI:
    REPORT_METADATA_WEB_MAP.append(
        {
            "name": "web_rpki",
            "type": "category",
            "translation_key": "siterpki",
            "children": [
                {
                    "name": "web_rpki",
                    "type": "section",
                    "translation_key": "domain rpki web-server",
                    "children": [
                        {
                            "name": "web_rpki_exists",
                            "name_on_report": "web_rpki_exists",
                            "type": "test",
                            "translation_key": "web rpki exists",
                        },
                        {
                            "name": "web_rpki_valid",
                            "name_on_report": "web_rpki_valid",
                            "type": "test",
                            "translation_key": "web rpki valid",
                        },
                    ],
                },
                {
                    "name": "web_ns_rpki",
                    "type": "section",
                    "translation_key": "domain-mail rpki name-servers",
                    "children": [
                        {
                            "name": "web_ns_rpki_exists",
                            "name_on_report": "ns_rpki_exists",
                            "type": "test",
                            "translation_key": "web-mail rpki ns-exists",
                        },
                        {
                            "name": "web_ns_rpki_valid",
                            "name_on_report": "ns_rpki_valid",
                            "type": "test",
                            "translation_key": "web-mail rpki ns-valid",
                        },
                    ],
                },
            ],
        },
    )


REPORT_METADATA_MAIL_MAP = []

if settings.INTERNET_NL_CHECK_SUPPORT_IPV6:
    REPORT_METADATA_MAIL_MAP.append(
        {
            "name": "mail_ipv6",
            "type": "category",
            "translation_key": "mailipv6",
            "children": [
                {
                    "name": "mail_ipv6_nameservers",
                    "type": "section",
                    "translation_key": "domain-mail ipv6 name-servers",
                    "children": [
                        {
                            "name": "mail_ipv6_ns_address",
                            "name_on_report": "ns_aaaa",
                            "type": "test",
                            "translation_key": "web-mail ipv6 ns-AAAA",
                        },
                        {
                            "name": "mail_ipv6_ns_reach",
                            "name_on_report": "ns_reach",
                            "type": "test",
                            "translation_key": "web-mail ipv6 ns-reach",
                        },
                    ],
                },
                {
                    "name": "mail_ipv6_mailserver",
                    "type": "section",
                    "translation_key": "mail ipv6 mail-servers",
                    "children": [
                        {
                            "name": "mail_ipv6_mx_address",
                            "name_on_report": "mx_aaaa",
                            "type": "test",
                            "translation_key": "mail ipv6 mx-AAAA",
                        },
                        {
                            "name": "mail_ipv6_mx_reach",
                            "name_on_report": "mx_reach",
                            "type": "test",
                            "translation_key": "mail ipv6 mx-reach",
                        },
                    ],
                },
            ],
        }
    )

if settings.INTERNET_NL_CHECK_SUPPORT_DNSSEC:
    REPORT_METADATA_MAIL_MAP.append(
        {
            "name": "mail_dnssec",
            "type": "category",
            "translation_key": "maildnssec",
            "children": [
                {
                    "name": "mail_dnssec_domain",
                    "type": "section",
                    "translation_key": "mail dnssec domain",
                    "children": [
                        {
                            "name": "mail_dnssec_mailto_exist",
                            "name_on_report": "dnssec_exists",
                            "type": "test",
                            "translation_key": "mail dnnsec exists",
                        },
                        {
                            "name": "mail_dnssec_mailto_valid",
                            "name_on_report": "dnssec_valid",
                            "type": "test",
                            "translation_key": "mail dnnsec valid",
                        },
                    ],
                },
                {
                    "name": "mail_dnssec_mailservers",
                    "type": "section",
                    "translation_key": "mail dnssec mail-servers",
                    "children": [
                        {
                            "name": "mail_dnssec_mx_exist",
                            "name_on_report": "dnssec_mx_exists",
                            "type": "test",
                            "translation_key": "mail dnnsec mx-exists",
                        },
                        {
                            "name": "mail_dnssec_mx_valid",
                            "name_on_report": "dnssec_mx_valid",
                            "type": "test",
                            "translation_key": "mail dnnsec mx-valid",
                        },
                    ],
                },
            ],
        }
    )

if settings.INTERNET_NL_CHECK_SUPPORT_MAIL:

    REPORT_METADATA_MAIL_MAP.append(
        {
            "name": "mail_auth",
            "type": "category",
            "translation_key": "mailauth",
            "children": [
                {
                    "name": "mail_auth_dmarc",
                    "type": "section",
                    "translation_key": "mail auth dmarc",
                    "children": [
                        {
                            "name": "mail_auth_dmarc_exist",
                            "name_on_report": "dmarc",
                            "type": "test",
                            "translation_key": "mail auth dmarc",
                        },
                        {
                            "name": "mail_auth_dmarc_policy",
                            "name_on_report": "dmarc_policy",
                            "type": "test",
                            "translation_key": "mail auth dmarc-policy",
                        },
                    ],
                },
                {
                    "name": "mail_auth_dkim",
                    "type": "section",
                    "translation_key": "mail auth dkim",
                    "children": [
                        {
                            "name": "mail_auth_dkim_exist",
                            "name_on_report": "dkim",
                            "type": "test",
                            "translation_key": "mail auth dkim",
                        },
                    ],
                },
                {
                    "name": "mail_auth_spf",
                    "type": "section",
                    "translation_key": "mail auth spf",
                    "children": [
                        {
                            "name": "mail_auth_spf_exist",
                            "name_on_report": "spf",
                            "type": "test",
                            "translation_key": "mail auth spf",
                        },
                        {
                            "name": "mail_auth_spf_policy",
                            "name_on_report": "spf_policy",
                            "type": "test",
                            "translation_key": "mail auth spf-policy",
                        },
                    ],
                },
            ],
        }
    )

if settings.INTERNET_NL_CHECK_SUPPORT_TLS:
    REPORT_METADATA_MAIL_MAP.append(
        {
            "name": "mail_starttls",
            "type": "category",
            "translation_key": "mailtls",
            "children": [
                {
                    "name": "mail_starttls_tls",
                    "type": "section",
                    "translation_key": "mail tls starttls",
                    "children": [
                        {
                            "name": "mail_starttls_tls_available",
                            "name_on_report": "starttls_exists",
                            "type": "test",
                            "translation_key": "mail tls starttls-exists",
                        },
                        {
                            "name": "mail_starttls_tls_version",
                            "name_on_report": "tls_version",
                            "type": "test",
                            "translation_key": "mail tls version",
                        },
                        {
                            "name": "mail_starttls_tls_ciphers",
                            "name_on_report": "tls_ciphers",
                            "type": "test",
                            "translation_key": "mail tls ciphers",
                        },
                        {
                            "name": "mail_starttls_tls_cipherorder",
                            "name_on_report": "tls_cipher_order",
                            "type": "test",
                            "translation_key": "mail tls cipher-order",
                        },
                        {
                            "name": "mail_starttls_tls_keyexchange",
                            "name_on_report": "fs_params",
                            "type": "test",
                            "translation_key": "mail tls fs-params",
                        },
                        {
                            "name": "mail_starttls_tls_keyexchangehash",
                            "name_on_report": "kex_hash_func",
                            "type": "test",
                            "translation_key": "mail tls kex-hash-func",
                        },
                        {
                            "name": "mail_starttls_tls_compress",
                            "name_on_report": "tls_compression",
                            "type": "test",
                            "translation_key": "mail tls compression",
                        },
                        {
                            "name": "mail_starttls_tls_secreneg",
                            "name_on_report": "renegotiation_secure",
                            "type": "test",
                            "translation_key": "mail tls renegotiation-secure",
                        },
                        {
                            "name": "mail_starttls_tls_clientreneg",
                            "name_on_report": "renegotiation_client",
                            "type": "test",
                            "translation_key": "mail tls renegotiation-client",
                        },
                        {
                            "name": "mail_starttls_tls_0rtt",
                            "name_on_report": "zero_rtt",
                            "type": "test",
                            "translation_key": "mail tls zero-rtt",
                        },
                    ],
                },
                {
                    "name": "mail_starttls_certificate",
                    "type": "section",
                    "translation_key": "domain-mail tls certificate",
                    "children": [
                        {
                            "name": "mail_starttls_cert_chain",
                            "name_on_report": "cert_trust",
                            "type": "test",
                            "translation_key": "mail tls cert-trust",
                        },
                        {
                            "name": "mail_starttls_cert_pubkey",
                            "name_on_report": "cert_pubkey",
                            "type": "test",
                            "translation_key": "mail tls cert-pubkey",
                        },
                        {
                            "name": "mail_starttls_cert_sig",
                            "name_on_report": "cert_signature",
                            "type": "test",
                            "translation_key": "mail tls cert-signature",
                        },
                        {
                            "name": "mail_starttls_cert_domain",
                            "name_on_report": "cert_hostmatch",
                            "type": "test",
                            "translation_key": "mail tls cert-hostmatch",
                        },
                    ],
                },
                {
                    "name": "mail_starttls_dane",
                    "type": "section",
                    "translation_key": "domain-mail tls dane",
                    "children": [
                        {
                            "name": "mail_starttls_dane_exist",
                            "name_on_report": "dane_exists",
                            "type": "test",
                            "translation_key": "mail tls dane-exists",
                        },
                        {
                            "name": "mail_starttls_dane_valid",
                            "name_on_report": "dane_valid",
                            "type": "test",
                            "translation_key": "mail tls dane-valid",
                        },
                        {
                            "name": "mail_starttls_dane_rollover",
                            "name_on_report": "dane_rollover",
                            "type": "test",
                            "translation_key": "mail tls dane-rollover",
                        },
                    ],
                },
            ],
        }
    )

if settings.INTERNET_NL_CHECK_SUPPORT_RPKI:
    REPORT_METADATA_MAIL_MAP.append(
        {
            "name": "mail_rpki",
            "type": "category",
            "translation_key": "mailrpki",
            "children": [
                {
                    "name": "mail_rpki",
                    "type": "section",
                    "translation_key": "mail rpki mail-servers",
                    "children": [
                        {
                            "name": "mail_rpki_exists",
                            "name_on_report": "mail_rpki_exists",
                            "type": "test",
                            "translation_key": "mail rpki exists",
                        },
                        {
                            "name": "mail_rpki_valid",
                            "name_on_report": "mail_rpki_valid",
                            "type": "test",
                            "translation_key": "mail rpki valid",
                        },
                    ],
                },
                {
                    "name": "mail_ns_rpki",
                    "type": "section",
                    "translation_key": "domain-mail rpki name-servers",
                    "children": [
                        {
                            "name": "mail_ns_rpki_exists",
                            "name_on_report": "ns_rpki_exists",
                            "type": "test",
                            "translation_key": "web-mail rpki ns-exists",
                        },
                        {
                            "name": "mail_ns_rpki_valid",
                            "name_on_report": "ns_rpki_valid",
                            "type": "test",
                            "translation_key": "web-mail rpki ns-valid",
                        },
                    ],
                },
                {
                    "name": "mail_mx_ns_rpki",
                    "type": "section",
                    "translation_key": "domain-mail rpki mx-name-servers",
                    "children": [
                        {
                            "name": "mail_mx_ns_rpki_exists",
                            "name_on_report": "mail_mx_ns_rpki_exists",
                            "type": "test",
                            "translation_key": "mail rpki mx-ns-exists",
                        },
                        {
                            "name": "mail_mx_ns_rpki_valid",
                            "name_on_report": "mail_mx_ns_rpki_valid",
                            "type": "test",
                            "translation_key": "mail rpki mx-ns-valid",
                        },
                    ],
                },
            ],
        },
    )
