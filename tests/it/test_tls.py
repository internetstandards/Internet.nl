import pytest
from helpers import DomainConfig, GoodDomain, BadDomain
from helpers import id_generator, TESTS, UX


domains_configured_to_pass = [
    # 0-RTT is a TLS 1.3 feature so should not be tested.
    GoodDomain('tls12only.test.nlnetlabs.nl', {TESTS.HTTPS_TLS_ZERO_RTT}),
    GoodDomain('tls1213.test.nlnetlabs.nl'),
    GoodDomain('tls1213sni.test.nlnetlabs.nl'),
    GoodDomain('tls12onlyffdhe3072.test.nlnetlabs.nl', {TESTS.HTTPS_TLS_ZERO_RTT}),
    GoodDomain('tls13only.test.nlnetlabs.nl'),
]

domains_configured_to_fail = [
    # no SSL means no HTTPS
    DomainConfig(
        'nossl.test.nlnetlabs.nl',
        expected_failures={
            TESTS.HTTPS_HTTP_HTTPS_AVAILABLE
        },
        expected_not_tested={
            TESTS.DANE_EXISTS,
            TESTS.DANE_VALID,
            TESTS.HTTPS_CERT_DOMAIN,
            TESTS.HTTPS_CERT_PUBKEY,
            TESTS.HTTPS_CERT_SIG,
            TESTS.HTTPS_CERT_TRUST,
            TESTS.HTTPS_HTTP_COMPRESSION,
            TESTS.HTTPS_HTTP_HSTS,
            TESTS.HTTPS_HTTP_REDIRECT,
            TESTS.HTTPS_TLS_CIPHER_SUITES,
            TESTS.HTTPS_TLS_CLIENT_RENEG,
            TESTS.HTTPS_TLS_COMPRESSION,
            TESTS.HTTPS_TLS_KEY_EXCHANGE,
            TESTS.HTTPS_TLS_OCSP_STAPLING,
            TESTS.HTTPS_TLS_SECURE_RENEG,
            TESTS.HTTPS_TLS_VERSION,
            TESTS.HTTPS_TLS_ZERO_RTT,
            TESTS.SECURITY_HTTP_CSP,
            TESTS.SECURITY_HTTP_REFERRER,
            TESTS.SECURITY_HTTP_XCONTYPE,
            TESTS.SECURITY_HTTP_XFRAME,
            TESTS.SECURITY_HTTP_XXSS,
        }),

    # This domain deliberately lacks an IPV6 AAAA record in DNS
    DomainConfig(
        'tls1213ipv4only.test.nlnetlabs.nl',
        expected_failures={
            TESTS.IPV6_WEB_ADDRESS
        },
        expected_not_tested={
            TESTS.IPV6_WEB_REACHABILITY,
            TESTS.IPV6_WEB_SAME_WEBSITE
        }),

    # This domain deliberately has no matching virtual host configuration on
    # the webserver that its DNS A and AAAA records resolve to.
    DomainConfig(
        'tls1213wrongcertname.test.nlnetlabs.nl',
        expected_failures={
            TESTS.HTTPS_CERT_DOMAIN,
        },
        expected_not_tested={
            TESTS.DANE_VALID
        }),

    # This website virtual host configuration deliberately fails to serve a
    # HSTS response header
    BadDomain('tls1213nohsts.test.nlnetlabs.nl', {TESTS.HTTPS_HTTP_HSTS}),

    # This website virtual host configuration deliberately serves a 'short'
    # HSTS response header.
    # TODO: Extend this test to detect that the report complains specifically
    # about a 'short' HSTS.
    BadDomain('tls1213shorthsts.test.nlnetlabs.nl', {TESTS.HTTPS_HTTP_HSTS}),

    # This website virtual host configuration deliberately does not do OCSP
    # stapling.
    BadDomain('tls1213noocspstaple.test.nlnetlabs.nl', {TESTS.HTTPS_TLS_OCSP_STAPLING}),

    # This website virtual host configuration deliberately supports 0-RTT
    # Note: if NGINX hasn't already fetched the OCSP responder response it will
    # not staple the OCSP responder data in the response to us and this test
    # will fail. NGINX should be configured to serve OCSP responder data from
    # a file to avoid this issue.
    BadDomain('tls130rtt.test.nlnetlabs.nl', {TESTS.HTTPS_TLS_ZERO_RTT}),
]

domains_with_phase_out_warnings = [
    # Our TLS 1.0 server uses the OpenSSL server binary which does not serve
    # HSTS response headers
    DomainConfig(
        'tls10only.test.nlnetlabs.nl',
        expected_failures={
            TESTS.HTTPS_HTTP_HSTS
        },
        expected_warnings={
            TESTS.HTTPS_TLS_VERSION: [
                ['TLS 1.0 (at risk)'],  # IPv6
                ['TLS 1.0 (at risk)'],  # IPv4
            ]
        },
        expected_not_tested={
            TESTS.HTTPS_TLS_ZERO_RTT
        }),

    # Our TLS 1.1 server uses the OpenSSL server binary which does not serve
    # HSTS response headers
    DomainConfig(
        'tls11only.test.nlnetlabs.nl',
        expected_failures={
            TESTS.HTTPS_HTTP_HSTS
        },
        expected_warnings={
            TESTS.HTTPS_TLS_VERSION: [
                ['TLS 1.1 (at risk)'],  # IPv6
                ['TLS 1.1 (at risk)'],  # IPv4
            ]
        },
        expected_not_tested={
            TESTS.HTTPS_TLS_ZERO_RTT
        }),

    # 0-RTT is a TLS 1.3 feature so should not be tested.
    # Finite-field group ffdhe2048 is listed as 'phase out' by NCSC 2.0 and
    # so should result in a perfect score and a warning about the ff group.
    DomainConfig(
        'tls12onlyffdhe2048.test.nlnetlabs.nl',
        expected_warnings={
            TESTS.HTTPS_TLS_KEY_EXCHANGE: [
                ['DH-FFDHE2048 (at risk)'],  # IPv6
                ['DH-FFDHE2048 (at risk)'],  # IPv4
            ]
        },
        expected_not_tested={
            TESTS.HTTPS_TLS_ZERO_RTT
        },
        expected_score='100%'),
]

mishandled_domains = [
    # internet.nl cannot make SSLv2 connections so instead of failing because
    # of the insecure TLS version it fails because it cannot detect HTTPS
    # support at al.
    pytest.param(
        BadDomain('ssl2only.test.nlnetlabs.nl', {TESTS.HTTPS_TLS_VERSION}),
        marks=pytest.mark.xfail),

    # internet.nl cannot make SSLv3 connections so instead of failing because
    # of the insecure TLS version it fails because it cannot detect HTTPS
    # support at al.
    pytest.param(
        BadDomain('ssl3only.test.nlnetlabs.nl', {TESTS.HTTPS_TLS_VERSION}),
        marks=pytest.mark.xfail),
]


def assess_website(selenium, domain_config):
    UX.submit_website_test_form(selenium, domain_config.domain)
    UX.wait_for_test_to_start(selenium, domain_config.domain)
    UX.wait_for_test_to_complete(selenium)
    UX.open_report_detail_sections(selenium)

    assert UX.get_failed_tests(selenium) == domain_config.expected_failures
    assert UX.get_nottested_tests(selenium) == domain_config.expected_not_tested

    if domain_config.expected_warnings is set:
        assert UX.get_warning_tests(selenium) == domain_config.expected_warnings
    elif domain_config.expected_warnings is dict:
        assert UX.get_warning_tests(selenium) == set(domain_config.expected_warnings.keys())
        for test_title, details in domain_config.expected_warnings:
            assert UX.get_table_values(selenium, test_title) == details

    if domain_config.expected_score:
        assert UX.get_score(selenium) == domain_config.expected_score


@pytest.mark.parametrize(
    'domain_config', domains_configured_to_pass, ids=id_generator)
def test_domains_configured_to_pass(selenium, domain_config):
    assess_website(selenium, domain_config)


@pytest.mark.parametrize(
    'domain_config', domains_with_phase_out_warnings, ids=id_generator)
def test_domains_with_phaseout_warnings(selenium, domain_config):
    assess_website(selenium, domain_config)


@pytest.mark.parametrize(
    'domain_config', domains_configured_to_fail, ids=id_generator)
def test_domains_configured_to_fail(selenium, domain_config):
    assess_website(selenium, domain_config)


@pytest.mark.parametrize(
    'domain_config', mishandled_domains, ids=id_generator)
def test_domains_mishandled_by_internetnl(selenium, domain_config):
    assess_website(selenium, domain_config)


# What do we want?
# - phased out configurations should be 100% score but warning status
