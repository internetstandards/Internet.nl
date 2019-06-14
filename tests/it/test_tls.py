# TODO: Use Selenium Page Objects
# Don't test the success percentage yet because the target servers use
# self-signed SSL certificates which do not pass the certificate trust
# chain test and thus we cannot achieve a 100% score. Also, a score of
# 100% doesn't say anything about how tests or which tests passed.

import pytest
from helpers import DomainConfig, id_generator, TESTS, UX


domains_configured_to_pass = [
    DomainConfig('tls1213.test.nlnetlabs.nl'),
    DomainConfig('tls1213sni.test.nlnetlabs.nl'),
    DomainConfig('tls12only.test.nlnetlabs.nl'),
    DomainConfig('tls13only.test.nlnetlabs.nl'),
]


domains_configured_to_fail = [
    # no SSL means no HTTPS
    DomainConfig(
        'nossl.test.nlnetlabs.nl',
        expected_failures={
            TESTS.HTTPS_AVAILABLE
        }),

    # Our TLS 1.0 server uses the OpenSSL server binary which does not serve
    # HSTS response headers
    # TODO: Extend this test to check that TLS 1.0 is flagged as phase out.
    DomainConfig(
        'tls10only.test.nlnetlabs.nl',
        expected_failures={
            TESTS.HSTS
        }),

    # Our TLS 1.1 server uses the OpenSSL server binary which does not serve
    # HSTS response headers
    # TODO: Extend this test to check that TLS 1.1 is flagged as phase out.
    DomainConfig(
        'tls11only.test.nlnetlabs.nl',
        expected_failures={
            TESTS.HSTS
        }),

    # This domain deliberately lacks an IPV6 AAAA record in DNS
    DomainConfig(
        'tls1213ipv4only.test.nlnetlabs.nl',
        expected_failures={
            TESTS.IPV6_ADDRESS_FOR_WEB_SERVER
        }),

    # This domain deliberately has no matching virtual host configuration on
    # the webserver that its DNS A and AAAA records resolve to.
    DomainConfig(
        'tls1213wrongcertname.test.nlnetlabs.nl',
        expected_failures={
            TESTS.DOMAIN_NAME_ON_CERT
        }),

    # This website virtual host configuration deliberately fails to serve a
    # HSTS response header
    DomainConfig(
        'tls1213nohsts.test.nlnetlabs.nl',
        expected_failures={
            TESTS.HSTS
        }),

    # This website virtual host configuration deliberately serves a 'short'
    # HSTS response header.
    # TODO: Extend this test to detect that the report complains specifically
    # about a 'short' HSTS.
    DomainConfig(
        'tls1213shorthsts.test.nlnetlabs.nl',
        expected_failures={
            TESTS.HSTS
        }),

    # This website virtual host configuration deliberately does not do OCSP
    # stapling.
    DomainConfig(
        'tls1213noocspstaple.test.nlnetlabs.nl',
        expected_failures={
            TESTS.OCSP_STAPLING
        }),

    # This website virtual host configuration deliberately supports 0-RTT
    DomainConfig(
        'tls130rtt.test.nlnetlabs.nl',
        expected_failures={
            TESTS.ZERO_RTT
        }),
]


mishandled_domains = [
    # internet.nl cannot make SSLv2 connections so instead of failing because
    # of the insecure TLS version it fails because it cannot detect HTTPS
    # support at al.
    pytest.param(
        DomainConfig(
            'ssl2only.test.nlnetlabs.nl',
            expected_failures={
                TESTS.TLS_VERSION
            }),
        marks=pytest.mark.xfail),

    # internet.nl cannot make SSLv3 connections so instead of failing because
    # of the insecure TLS version it fails because it cannot detect HTTPS
    # support at al.
    pytest.param(
        DomainConfig(
            'ssl3only.test.nlnetlabs.nl',
            expected_failures={
                TESTS.TLS_VERSION
            }),
        marks=pytest.mark.xfail),
]


def assess_website(selenium, domain_config):
    UX.submit_website_test_form(selenium, domain_config.domain)
    UX.wait_for_test_to_start(selenium, domain_config.domain)
    UX.wait_for_test_to_complete(selenium)
    UX.open_report_detail_sections(selenium)
    assert UX.get_failed_tests(selenium) == domain_config.expected_failures


@pytest.mark.parametrize(
    'domain_config', domains_configured_to_pass, ids=id_generator)
def test_domains_configured_to_pass(selenium, domain_config):
    assess_website(selenium, domain_config)


@pytest.mark.parametrize(
    'domain_config', domains_configured_to_fail, ids=id_generator)
def test_domains_configured_to_fail(selenium, domain_config):
    assess_website(selenium, domain_config)


@pytest.mark.parametrize(
    'domain_config', mishandled_domains, ids=id_generator)
def test_domains_mishandled_by_internetnl(selenium, domain_config):
    assess_website(selenium, domain_config)
