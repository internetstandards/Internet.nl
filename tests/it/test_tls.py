import pytest
import re
from helpers import DomainConfig, GoodDomain, BadDomain
from helpers import id_generator, TESTS, UX, IMPERFECT_SCORE, PERFECT_SCORE


# TODO: Refactor cipher tests to explicitly test for the expected ciphers in
# the right order (overlaps with testing of cipher preference order checking,
# which is not implemented yet).
# TODO: Report and test for IANA/RFC cipher names instead of OpenSSL cipher
# names?


# Cipher testing
# NCSC 2.0 defines a set of phase out ciphers. Here are the OpenSSL equivalent
# cipher names. Uses mappings taken from openssl 1.1.1b "ciphers" command, e.g.
#
#   openssl ciphers -V -psk -srp -stdname ALL@SECLEVEL=0 | fgrep <cipher name>
#
# Where this did not contain a match, the cipher name was looked up on
# https://testssl.sh/openssl-iana.mapping.html and then checked to see if
# openssl 1.0.2e knows it with this command (on any Docker container based on
# the 'targetbase' image):
#
#   /opt/openssl-old/bin/openssl ciphers -V <openssl cipher name>
#
# NCSC 2.0/RFC/IANA cipher name          OpenSSL cipher name    OpenSSL version
# -----------------------------------------------------------------------------
# TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA  ECDHE-ECDSA-DES-CBC3-SHA    1.0.2e
# TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA    ECDHE-RSA-DES-CBC3-SHA      1.0.2e
# TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA      EDH-RSA-DES-CBC3-SHA        1.0.2e
# TLS_RSA_WITH_AES_256_GCM_SHA384        AES256-GCM-SHA384           1.1.1b
# TLS_RSA_WITH_AES_128_GCM_SHA256        AES128-GCM-SHA256           1.1.1b
# TLS_RSA_WITH_AES_256_CBC_SHA256        AES256-SHA256               1.1.1b
# TLS_RSA_WITH_AES_256_CBC_SHA           AES256-SHA                  1.1.1b
# TLS_RSA_WITH_AES_128_CBC_SHA256        AES128-SHA256               1.1.1b
# TLS_RSA_WITH_AES_128_CBC_SHA           AES128-SHA                  1.1.1b
# TLS_RSA_WITH_3DES_EDE_CBC_SHA          DES-CBC3-SHA                1.0.2e
#
# These ciphers have the following properties according to 'ciphers -V':
#
# OpenSSL cipher name       code       protocol  kx    au     enc          mac
# -----------------------------------------------------------------------------
# ECDHE-ECDSA-DES-CBC3-SHA  0xC0,0x08  SSLv3     ECDH  ECDSA  3DES(168)    SHA1
# ECDHE-RSA-DES-CBC3-SHA    0xC0,0x12  SSLv3     ECDH  RSA    3DES(168)    SHA1
# EDH-RSA-DES-CBC3-SHA      0x00,0x16  SSLv3     DH    RSA    3DES(168)    SHA1
# AES256-GCM-SHA384         0x00,0x9D  TLSv1.2   RSA   RSA    AESGCM(256)  AEAD
# AES128-GCM-SHA256         0x00,0x9C  TLSv1.2   RSA   RSA    AESGCM(128)  AEAD
# AES256-SHA256             0x00,0x3D  TLSv1.2   RSA   RSA    AES(256)     SHA256
# AES256-SHA                0x00,0x35  SSLv3     RSA   RSA    AES(256)     SHA1
# AES128-SHA256             0x00,0x3C  TLSv1.2   RSA   RSA    AES(128)     SHA256
# AES128-SHA                0x00,0x2F  SSLv3     RSA   RSA    AES(128)     SHA1
# DES-CBC3-SHA              0x00,0x0A  SSLv3     RSA   RSA    3DES(168)    SHA1
REGEX_LEGACY_BAD_CIPHERS = re.compile(r'(IDEA|DES|RC4|NULL)')
REGEX_MODERN_BAD_CIPHERS = re.compile(r'AES(128|256)-CCM')
REGEX_PHASE_OUT_CIPHERS = re.compile(r'(DES.+CBC3|3DES.+CBC|AES(128|256)-(GCM-SHA(256|384)|SHA(256)?)).* \(at risk\)')


# Some of the "mock" target servers are powered by OpenSSL server which cannot
# be configured to serve specific HTTP responses headers (e.g. HSTS) in
# combination with OCSP stapling, thus we have to accept these failures when
# using such a server.
class OpenSSLServerDomainConfig(DomainConfig):
    def __init__(self, test_id, domain, expected_warnings=dict(),
            expected_failures=dict(), manual_cipher_checks=False):
        self._manual_cipher_checks = manual_cipher_checks
        super().__init__(test_id, domain, expected_warnings=expected_warnings,
            expected_failures=expected_failures)

    def override_defaults(self):
        # This also means that the ciphers supported do not pass the Internet
        # NL tests, so unless the test is doing something specific with ciphers
        # we assume that the tests will warn that the server supports "phase
        # out" ciphers.
        if not self._manual_cipher_checks:
            self.expected_warnings.setdefault(
                TESTS.HTTPS_TLS_CIPHER_SUITES, [[REGEX_PHASE_OUT_CIPHERS]])

        # Since we can't control the HTTP response headers produced by the
        # OpenSSL 'www' server that means that HTTP response header related
        # tests will fail. The HTTP security tests produce a warning when they
        # fail.
        self.expected_failures.setdefault(TESTS.HTTPS_HTTP_HSTS, None)
        for test in (
            TESTS.SECURITY_HTTP_REFERRER,
            TESTS.SECURITY_HTTP_XCONTYPE,
            TESTS.SECURITY_HTTP_XFRAME,
            TESTS.SECURITY_HTTP_XXSS
        ):
            self.expected_warnings.setdefault(test, None)


class PreTLS12DomainConfig(DomainConfig):
    def override_defaults(self):
        self.expected_warnings.setdefault(TESTS.HTTPS_TLS_KEY_EXCHANGE, [
            [re.compile(r'(MD5|SHA1) \(at risk\)')],  # matches all rows
        ])


class PreTLS13DomainConfig(DomainConfig):
    def __init__(self, test_id, domain, expected_warnings=dict(),
            expected_failures=dict(), expected_not_tested=dict(), lang='en'):
        super().__init__(test_id, domain,
            expected_warnings=expected_warnings,
            expected_failures=expected_failures,
            expected_not_tested=expected_not_tested)

        # Only TLS 1.3 servers support 0-RTT
        if lang == 'en':
            self.expected_not_tested.setdefault(TESTS.HTTPS_TLS_ZERO_RTT, None)
        elif lang == 'nl':
            self.expected_not_tested.setdefault(TESTS.HTTPS_TLS_ZERO_RTT_NL, None)
        else:
            raise ValueError()


# Tests specifically intended to show that Internet.NL tests for compliance
# with the NCSC 2.0 guidelines.
ncsc_20_tests = [
    # For some reason even in SSLV23 mode (negotiate best protocol version)
    # the NASSL LegacySslClient sends TLS 1.0 HelloClient messages to the SSL2
    # only server which rejects them. The server works fine when connected to
    # by /opt/openssl-old/bin/openssl s_client -ssl2 -connect localhost:433.
    # Interestingly it also fails if -ssl2 is NOT passed to the openssl
    # command. I'm not going to modify Internet.NL at this point to make an
    # explicit attempt to connect using SSLv2 as current production Internet.NL
    # can't connect to SSLv2 or even SSLv3 servers so this is not a priority
    # right now. As such, instead of just failing because of the legacy
    # protocol version it also fails the "HTTPS available" test.
    pytest.param(
        OpenSSLServerDomainConfig('NCSC20-Table1:SSL20',
            'ssl2only.test.nlnetlabs.tk',
            expected_failures={
                TESTS.HTTPS_TLS_VERSION,
            }),
        marks=pytest.mark.xfail),

    # internet.nl cannot make SSLv3 connections so instead of failing because
    # of the insecure TLS version it fails because it cannot detect HTTPS
    # support at all.
    DomainConfig('NCSC20-Table1:SSL30',
        'ssl3only.test.nlnetlabs.tk',
        expected_failures={
            TESTS.HTTPS_TLS_VERSION,
            TESTS.HTTPS_TLS_CIPHER_SUITES,
            TESTS.HTTPS_TLS_CIPHER_ORDER,
            TESTS.HTTPS_TLS_CLIENT_RENEG,
            TESTS.HTTPS_TLS_SECURE_RENEG,
            TESTS.HTTPS_TLS_KEY_EXCHANGE,
        }),

    PreTLS12DomainConfig('NCSC20-Table1:TLS10',
        'tls10only.test.nlnetlabs.tk',
        expected_warnings={
            TESTS.HTTPS_TLS_VERSION: [
                ['TLS 1.0 (at risk)'],  # IPv6
                ['TLS 1.0 (at risk)'],  # IPv4
            ]
        }),

    PreTLS12DomainConfig('NCSC20-GuidelineB2-5:TLS10',
        'tls10onlyhonorclientcipherorder.test.nlnetlabs.tk',
        expected_warnings={
            TESTS.HTTPS_TLS_VERSION: [
                ['TLS 1.0 (at risk)'],  # IPv6
                ['TLS 1.0 (at risk)'],  # IPv4
            ]
        },
        expected_failures={
            TESTS.HTTPS_TLS_CIPHER_ORDER
        }),

    DomainConfig('NCSC20'
        '-Table12:TLS10',
        'tls10onlyinsecurereneg.test.nlnetlabs.tk',
        expected_warnings={
            TESTS.HTTPS_TLS_VERSION: [
                ['TLS 1.0 (at risk)'],  # IPv6
                ['TLS 1.0 (at risk)'],  # IPv4
            ]
        },
        expected_failures={
            TESTS.HTTPS_TLS_CIPHER_ORDER,
            TESTS.HTTPS_TLS_CIPHER_SUITES,
            TESTS.HTTPS_TLS_CLIENT_RENEG,
            TESTS.HTTPS_TLS_SECURE_RENEG,
            TESTS.HTTPS_TLS_KEY_EXCHANGE,
        }),

    PreTLS12DomainConfig('NCSC20-Table1:TLS11',
        'tls11only.test.nlnetlabs.tk',
        expected_warnings={
            TESTS.HTTPS_TLS_VERSION: [
                ['TLS 1.1 (at risk)'],  # IPv6
                ['TLS 1.1 (at risk)'],  # IPv4
            ],
        }),

    PreTLS12DomainConfig('NCSC20-Table1:TLS1011',
        'tls1011.test.nlnetlabs.tk',
        expected_warnings={
            TESTS.HTTPS_TLS_VERSION: [
                ['TLS 1.1 (at risk)'],  # IPv6
                ['TLS 1.0 (at risk)'],  # IPv6
                ['TLS 1.1 (at risk)'],  # IPv4
                ['TLS 1.0 (at risk)'],  # IPv4
            ],
        }),

    PreTLS12DomainConfig('NCSC20-Table1:TLS1112',
        'tls1112.test.nlnetlabs.tk',
        expected_warnings={
            TESTS.HTTPS_TLS_VERSION: [
                ['TLS 1.1 (at risk)'],  # IPv6
                ['TLS 1.1 (at risk)'],  # IPv4
            ]
        }),

    GoodDomain('NCSC20'
        '-Table1:TLS12'
        '-Table10:FFDHE4096',
        'tls12only.test.nlnetlabs.tk'),

    GoodDomain('NCSC20'
        '-Table1:TLS1213'
        '-Table2:RSAEXPPSK'
        '-Table3:MD5'
        '-Table11:No'
        '-Table12:Off'
        '-Table13:Off'
        '-Table14:NA'
        '-Table15:On',
        'tls1213.test.nlnetlabs.tk'),

    GoodDomain('NCSC20-Table1:TLS1213SNI',
        'tls1213sni.test.nlnetlabs.tk'),

    # This domain deliberately has no matching virtual host configuration on
    # the webserver that its DNS A and AAAA records resolve to.
    DomainConfig('NCSC20-Table1:TLS1213SNIWRONGCERT',
        'tls1213wrongcertname.test.nlnetlabs.tk',
        expected_failures={
            TESTS.HTTPS_CERT_DOMAIN,
        },
        expected_not_tested={
            TESTS.DANE_VALID
        }),

    GoodDomain('NCSC20'
        '-Table1:TLS13'
        '-Table14:Off',
        'tls13only.test.nlnetlabs.tk'),

    DomainConfig('NCSC20-Table1:None',
        'nossl.test.nlnetlabs.tk',
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
            TESTS.HTTPS_TLS_CIPHER_ORDER,
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

    # Old OpenSSL is used because it supports the bad ciphers that we want to
    # test for. For TLS 1.2 we normally use modern OpenSSL which has support
    # for disabling client renegotiation, but old OpenSSL does not have such
    # support so we have to expect the client renegotiation test to fail in
    # addition to the usual tests that fail when testing against an OpenSSL
    # server.
    DomainConfig('NCSC20'
        '-Table1:TLS12'
        '-Table6:LegacyBadCiphers',
        'tls12onlylegacybadciphers.test.nlnetlabs.tk',
        expected_failures={
            TESTS.HTTPS_TLS_CIPHER_SUITES: [
                [REGEX_LEGACY_BAD_CIPHERS],  # matches all rows
            ]
        }),
    DomainConfig('NCSC20'
        '-Table1:TLS12'
        '-Table6:LegacyPhaseOutCiphers',
        'tls12onlylegacyphaseoutciphers.test.nlnetlabs.tk',
        expected_warnings={
            TESTS.HTTPS_TLS_CIPHER_SUITES: [
                [REGEX_PHASE_OUT_CIPHERS],   # matches all remaining rows
            ]
        }),
    DomainConfig('NCSC20'
        '-Table1:TLS12'
        '-Table6:ModernPhaseOutCiphers',
        'tls12onlymodernphaseoutciphers.test.nlnetlabs.tk',
        expected_warnings={
            TESTS.HTTPS_TLS_CIPHER_SUITES: [
                [REGEX_PHASE_OUT_CIPHERS],   # matches all remaining rows
            ],
        }),
    # This test is an expected failure because currently only ModernConnection
    # can connect using the AESCCM8 cipher to TLS 1.2, yet we deliberately only
    # use ModernConnection for TLS 1.3, not for TLS 1.2. This results in
    # DebugConnection trying and failing to connect to the server with TLS 1.2
    # due to the lack of shared ciphers.
    pytest.param(DomainConfig('NCSC20'
        '-Table1:TLS12'
        '-Table6:ModernBadCiphers',
        'tls12onlymodernbadciphers.test.nlnetlabs.tk',
        expected_failures={
            TESTS.HTTPS_TLS_CIPHER_SUITES: [
                [REGEX_MODERN_BAD_CIPHERS],  # matches all rows
            ],
        }), marks=pytest.mark.xfail),

    # 0-RTT is a TLS 1.3 feature so should not be tested.
    # Finite-field group ffdhe2048 is listed as 'phase out' by NCSC 2.0 and
    # so should result in a perfect score and a warning about the ff group.
    DomainConfig('NCSC20'
        '-Table1:TLS12'
        '-Table10:FFDHE2048',
        'tls12onlyffdhe2048.test.nlnetlabs.tk',
        expected_warnings={
            TESTS.HTTPS_TLS_KEY_EXCHANGE: [
                [re.compile(r'(RSASSA-PSS|DH-FFDHE2048).+')]
            ]
        }),

    GoodDomain('NCSC20'
        '-Table1:TLS12'
        '-Table10:FFDHE3072',
        'tls12onlyffdhe3072.test.nlnetlabs.tk'),

    # This domain doesn't use an NCSC 2.0 approved DH finite-field group.
    DomainConfig('NCSC20'
        '-Table1:TLS12'
        '-Table10:OtherGroups',
        'tls12onlyffother.test.nlnetlabs.tk',
        expected_failures={
            TESTS.HTTPS_TLS_KEY_EXCHANGE: [
                [re.compile(r'(RSASSA-PSS.+\(at risk\)|DH-4096)')],
            ]
        }),

    DomainConfig('NCSC20'
        '-Table1:TLS12'
        '-Table5:No',
        'tls12onlynosha2.test.nlnetlabs.tk',
        expected_warnings={
            TESTS.HTTPS_TLS_KEY_EXCHANGE
        }),

    DomainConfig('NCSC20'
        '-Table11:TLS12'
        '-Table13:TLS12',
        'tls1213tlscompression.test.nlnetlabs.tk',
        expected_failures={
            TESTS.HTTPS_TLS_COMPRESSION
        }),

    # This website virtual host configuration deliberately does not do OCSP
    # stapling.
    DomainConfig('NCSC20'
        '-Table1:TLS1213'
        '-Table15:Off',
        'tls1213noocspstaple.test.nlnetlabs.tk',
        expected_passes={
            TESTS.HTTPS_TLS_OCSP_STAPLING: [
                ['no'],  # IPv6
                ['no'],  # IPv4
            ]
        },
        expected_score=PERFECT_SCORE),

    # NOTE: at the time of writing the target server for this test also
    # supports SHA2 as well as SHA1. Interpreting the NCSC 2.0 document
    # literally would mean that we consider this NOT to be a warning because
    # it's only phase out if SHA2 is NOT supported, irrespective of whether
    # SHA1 is supported. However, we have decided that like the rest of NCSC
    # 2.0 we think allowing the client to negotiate a weaker hash function with
    # the server is a bad thing and thus support for non-SHA2 is a warning.
    DomainConfig('NCSC20'
        '-Table1:TLS12'
        '-Table5:No',
        'tls13onlynosha2.test.nlnetlabs.tk',
        expected_warnings={
            TESTS.HTTPS_TLS_KEY_EXCHANGE
        }),

    # This website virtual host configuration deliberately supports 0-RTT
    # Note: if NGINX hasn't already fetched the OCSP responder response it will
    # not staple the OCSP responder data in the response to us and this test
    # will fail. NGINX should be configured to serve OCSP responder data from
    # a file to avoid this issue.
    BadDomain('NCSC20'
        '-Table1:TLS13'
        '-Table14:On',
        'tls130rtt.test.nlnetlabs.tk',
        {TESTS.HTTPS_TLS_ZERO_RTT}),

    # This website virtual host configuration deliberately serves an OCSP
    # response that was obtained for a different domain/cert and so is invalid
    # for this domain/cert.
    BadDomain('NCSC20'
        '-Table1:TLS13'
        '-Table15:OnInvalid',
        'tls13invalidocsp.test.nlnetlabs.tk',
        expected_failures={
            TESTS.HTTPS_TLS_OCSP_STAPLING: [
                ['no'],  # IPv6
                ['no'],  # IPv4
            ]
        }),

    BadDomain('NCSC20-GuidelineB2-5:TLS13',
        'tls13onlyhonorclientcipherorder.test.nlnetlabs.tk',
        expected_failures={
            TESTS.HTTPS_TLS_CIPHER_ORDER
        }),
]

other_tests = [
    # This website virtual host configuration deliberately fails to serve a
    # HSTS response header
    DomainConfig('HSTS:NONE',
        'tls1213nohsts.test.nlnetlabs.tk',
        expected_failures={
            TESTS.HTTPS_HTTP_HSTS
        }),

    # This website virtual host configuration deliberately serves a 'short'
    # HSTS response header.
    DomainConfig('HSTS:SHORT',
        'tls1213shorthsts.test.nlnetlabs.tk',
        expected_failures={
            TESTS.HTTPS_HTTP_HSTS: [
                ['max-age=1000; includeSubdomains;'],  # IPv6
                ['max-age=1000; includeSubdomains;']   # IPv4
            ]
        }),

    # This domain deliberately lacks an IPV6 AAAA record in DNS
    DomainConfig('IPV6:NONE',
        'tls1213ipv4only.test.nlnetlabs.tk',
        expected_failures={
            TESTS.IPV6_WEB_ADDRESS
        },
        expected_not_tested={
            TESTS.IPV6_WEB_REACHABILITY,
            TESTS.IPV6_WEB_SAME_WEBSITE
        }),

    # This domain deliberately serves different response content on IPv4
    # than on IPv6
    DomainConfig('IPV6:DIFFTOIPV4',
        'tls13onlydiffipv4ipv6.test.nlnetlabs.tk',
        expected_failures={
            TESTS.IPV6_WEB_SAME_WEBSITE
        }),
]


nl_translation_tests = [
    PreTLS13DomainConfig('NCSC20-Table1:TLS10',
        'tls10only.test.nlnetlabs.tk',
        expected_warnings={
            TESTS.HTTPS_TLS_VERSION_NL: [
                ['TLS 1.0 (op risico)'],  # IPv6
                ['TLS 1.0 (op risico)'],  # IPv4
            ],
            TESTS.HTTPS_TLS_KEY_EXCHANGE_NL: [
                [r'(MD5|SHA1) \(op risico\)'],  # matches all rows
            ]
        },
        lang='nl'),
]


# Compare the test 'Technical details' table cells against expectations, if
# defined.
def check_table(selenium, expectation):
    for test_title, expected_details_table in expectation.items():
        if expected_details_table:
            regex_mode = False
            # for each row in the report table:
            for i, row in enumerate(UX.get_table_values(selenium, test_title)):
                # In regex_mode if there are fewer expectation rows than actual
                # report rows. then the regexes from the last expectation row
                # are compared against all remaining actual report rows. Having
                # fewer expected rows than actual report rows is otherwise an
                # unexpected mismatch.
                if i < len(expected_details_table):
                    expected_row = expected_details_table[i]
                else:
                    assert regex_mode is True

                # for each column in the row:
                for j, col in enumerate(row):
                    expected_col = expected_row[j]

                    if isinstance(expected_col, re.Pattern):
                        # compare the report table cell to the regular
                        # expression that the last expectation row contained:
                        regex_mode = True
                        assert expected_col.search(col) is not None
                    else:
                        # compare the report table cell to the expected cell at
                        # that position
                        assert col == expected_col


def assess_website(selenium, domain_config, lang='en'):
    UX.submit_website_test_form(selenium, domain_config.domain, lang)
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


@pytest.mark.parametrize(
    'domain_config', nl_translation_tests, ids=id_generator)
def test_translations(selenium, domain_config):
    assess_website(selenium, domain_config, 'nl')
