import pytest
from helpers import DomainConfig, GoodDomain, BadDomain
from helpers import id_generator, TESTS, UX, IMPERFECT_SCORE, PERFECT_SCORE


# Some of the "mock" target servers are powered by OpenSSL server which cannot
# serve HSTS response headers in combination with the other options we use,
# thus we have to accept this failure when using such a server.
class OpenSSLServerDomainConfig(DomainConfig):
    def __init__(self, test_id, domain, expected_warnings=dict()):
        super().__init__(test_id, domain, expected_warnings=expected_warnings)
        self.expected_not_tested.setdefault(TESTS.HTTPS_TLS_ZERO_RTT, None)
        self.expected_failures.setdefault(TESTS.HTTPS_HTTP_HSTS, None)
        for test in (
            TESTS.SECURITY_HTTP_REFERRER,
            TESTS.SECURITY_HTTP_XCONTYPE,
            TESTS.SECURITY_HTTP_XFRAME,
            TESTS.SECURITY_HTTP_XXSS
        ):
            self.expected_warnings.setdefault(test, None)


ncsc_20_tests = [
    # internet.nl cannot make SSLv2 connections so instead of failing because
    # of the insecure TLS version it fails because it cannot detect HTTPS
    # support at all.
    pytest.param(
        BadDomain('NCSC20-Table1:SSL20',
            'ssl2only.test.nlnetlabs.nl', {TESTS.HTTPS_TLS_VERSION}),
        marks=pytest.mark.xfail),

    # internet.nl cannot make SSLv3 connections so instead of failing because
    # of the insecure TLS version it fails because it cannot detect HTTPS
    # support at all.
    pytest.param(
        BadDomain('NCSC20-Table1:SSL30',
            'ssl3only.test.nlnetlabs.nl', {TESTS.HTTPS_TLS_VERSION}),
        marks=pytest.mark.xfail),

    OpenSSLServerDomainConfig('NCSC20-Table1:TLS10',
        'tls10only.test.nlnetlabs.nl',
        expected_warnings={
            TESTS.HTTPS_TLS_VERSION: [
                ['TLS 1.0 (at risk)'],  # IPv6
                ['TLS 1.0 (at risk)'],  # IPv4
            ]
        }),

    OpenSSLServerDomainConfig('NCSC20-Table1:TLS11',
        'tls11only.test.nlnetlabs.nl',
        expected_warnings={
            TESTS.HTTPS_TLS_VERSION: [
                ['TLS 1.1 (at risk)'],  # IPv6
                ['TLS 1.1 (at risk)'],  # IPv4
            ]
        }),

    OpenSSLServerDomainConfig('NCSC20-Table1:TLS1011',
        'tls1011.test.nlnetlabs.nl',
        expected_warnings={
            TESTS.HTTPS_TLS_VERSION: [
                ['TLS 1.1 (at risk)'],  # IPv6
                ['TLS 1.0 (at risk)'],  # IPv6
                ['TLS 1.1 (at risk)'],  # IPv4
                ['TLS 1.0 (at risk)'],  # IPv4
            ]
        }),

    OpenSSLServerDomainConfig('NCSC20-Table1:TLS1112',
        'tls1112.test.nlnetlabs.nl',
        expected_warnings={
            TESTS.HTTPS_TLS_VERSION: [
                ['TLS 1.1 (at risk)'],  # IPv6
                ['TLS 1.1 (at risk)'],  # IPv4
            ]
        }),

    GoodDomain('NCSC20'
        '-Table1:TLS12'
        '-Table10:FFDHE4096',
        'tls12only.test.nlnetlabs.nl',
        {TESTS.HTTPS_TLS_ZERO_RTT}),

    GoodDomain('NCSC20'
        '-Table1:TLS1213'
        '-Table2:RSAEXPPSK'
        '-Table3:MD5'
        '-Table11:No'
        '-Table12:Off'
        '-Table13:Off'
        '-Table14:NA'
        '-Table15:On',
        'tls1213.test.nlnetlabs.nl'),

    GoodDomain('NCSC20-Table1:TLS1213SNI',
        'tls1213sni.test.nlnetlabs.nl'),

    # This domain deliberately has no matching virtual host configuration on
    # the webserver that its DNS A and AAAA records resolve to.
    DomainConfig('NCSC20-Table1:TLS1213SNIWRONGCERT',
        'tls1213wrongcertname.test.nlnetlabs.nl',
        expected_failures={
            TESTS.HTTPS_CERT_DOMAIN,
        },
        expected_not_tested={
            TESTS.DANE_VALID
        }),

    GoodDomain('NCSC20'
        '-Table1:TLS13'
        '-Table14:Off',
        'tls13only.test.nlnetlabs.nl'),

    DomainConfig('NCSC20-Table1:None',
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

    # 0-RTT is a TLS 1.3 feature so should not be tested.
    # Finite-field group ffdhe2048 is listed as 'phase out' by NCSC 2.0 and
    # so should result in a perfect score and a warning about the ff group.
    DomainConfig('NCSC20-Table10:FFDHE2048',
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

    GoodDomain('NCSC20-Table10:FFDHE3072',
        'tls12onlyffdhe3072.test.nlnetlabs.nl',
        {TESTS.HTTPS_TLS_ZERO_RTT}),

    # This domain doesn't use an NCSC 2.0 approved DH finite-field group.
    DomainConfig('NCSC20-Table10:OtherGroups',
        'tls12onlyffother.test.nlnetlabs.nl',
        expected_failures={
            TESTS.HTTPS_TLS_KEY_EXCHANGE: [
                ['DH-4096 (insufficient)'],  # IPv6
                ['DH-4096 (insufficient)'],  # IPv4
            ]
        },
        expected_not_tested={
            TESTS.HTTPS_TLS_ZERO_RTT
        }),

    # This website virtual host configuration deliberately supports 0-RTT
    # Note: if NGINX hasn't already fetched the OCSP responder response it will
    # not staple the OCSP responder data in the response to us and this test
    # will fail. NGINX should be configured to serve OCSP responder data from
    # a file to avoid this issue.
    BadDomain('NCSC20-Table14:On',
        'tls130rtt.test.nlnetlabs.nl',
        {TESTS.HTTPS_TLS_ZERO_RTT}),

    # This website virtual host configuration deliberately does not do OCSP
    # stapling.
    DomainConfig('NCSC20-Table15:Off',
        'tls1213noocspstaple.test.nlnetlabs.nl',
        expected_passes={
            TESTS.HTTPS_TLS_OCSP_STAPLING: [
                ['no'],  # IPv6
                ['no'],  # IPv4
            ]
        },
        expected_score=PERFECT_SCORE),

    # This website virtual host configuration deliberately serves an OCSP
    # response that was obtained for a different domain/cert and so is invalid
    # for this domain/cert.
    BadDomain('NCSC20-Table15:OnInvalid',
        'tls13invalidocsp.test.nlnetlabs.nl',
        expected_failures={
            TESTS.HTTPS_TLS_OCSP_STAPLING: [
                ['no'],  # IPv6
                ['no'],  # IPv4
            ]
        }),

    OpenSSLServerDomainConfig('NCSC20-Table5:No',
        'tls12onlynosha2.test.nlnetlabs.nl',
        expected_warnings={
            TESTS.HTTPS_TLS_KEY_EXCHANGE: [
                ['SHA1 (at risk)'],  # IPv6
                ['SHA1 (at risk)'],  # IPv4
            ]
        }),
]

other_tests = [
    # This website virtual host configuration deliberately fails to serve a
    # HSTS response header
    BadDomain('HSTS:NONE', 'tls1213nohsts.test.nlnetlabs.nl',
        {TESTS.HTTPS_HTTP_HSTS}),

    # This website virtual host configuration deliberately serves a 'short'
    # HSTS response header.
    BadDomain('HSTS:SHORT', 'tls1213shorthsts.test.nlnetlabs.nl',
        {
            TESTS.HTTPS_HTTP_HSTS: [
                ['max-age=1000; includeSubdomains;'],  # IPv6
                ['max-age=1000; includeSubdomains;']   # IPv4
            ]
        }),

    # This domain deliberately lacks an IPV6 AAAA record in DNS
    DomainConfig('IPV6:NONE',
        'tls1213ipv4only.test.nlnetlabs.nl',
        expected_failures={
            TESTS.IPV6_WEB_ADDRESS
        },
        expected_not_tested={
            TESTS.IPV6_WEB_REACHABILITY,
            TESTS.IPV6_WEB_SAME_WEBSITE
        }),
]


def check_table(selenium, expectation):
    for test_title, details in expectation.items():
        if details:
            assert UX.get_table_values(selenium, test_title) == details


def assess_website(selenium, domain_config):
    UX.submit_website_test_form(selenium, domain_config.domain)
    UX.wait_for_test_to_start(selenium, domain_config.domain)
    UX.wait_for_test_to_complete(selenium)
    UX.open_report_detail_sections(selenium)

    assert (UX.get_failed_tests(selenium)
        == set(domain_config.expected_failures.keys()))
    assert (UX.get_nottested_tests(selenium)
        == set(domain_config.expected_not_tested.keys()))
    assert (UX.get_warning_tests(selenium)
        == set(domain_config.expected_warnings.keys()))

    check_table(selenium, domain_config.expected_failures)
    check_table(selenium, domain_config.expected_not_tested)
    check_table(selenium, domain_config.expected_warnings)
    check_table(selenium, domain_config.expected_passes)

    if domain_config.expected_score:
        score_as_percentage_str = UX.get_score(selenium)
        if domain_config.expected_score == IMPERFECT_SCORE:
            score_as_int = int(score_as_percentage_str.strip('%'))
            assert score_as_int > 0 and score_as_int < 100
        else:
            assert score_as_percentage_str == domain_config.expected_score


@pytest.mark.parametrize(
    'domain_config', ncsc_20_tests, ids=id_generator)
def test_ncsc_20(selenium, domain_config):
    assess_website(selenium, domain_config)


@pytest.mark.parametrize(
    'domain_config', other_tests, ids=id_generator)
def test_others(selenium, domain_config):
    assess_website(selenium, domain_config)
