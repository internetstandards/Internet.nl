import pytest
import re
from helpers import DomainConfig, GoodDomain, BadDomain
from helpers import domainconfig_id_generator, TESTS, UX
from helpers import IMPERFECT_SCORE, PERFECT_SCORE
from helpers import PHASE_OUT_TEXT, PHASE_OUT_TEXT_NL, ANY


# TODO: Refactor cipher tests to explicitly test for the expected ciphers in
# the right order (overlaps with testing of cipher preference order checking,
# which is not implemented yet).
# TODO: Report and test for IANA/RFC cipher names instead of OpenSSL cipher
# names?


class DetailTableCellMatcher:
    def matches(self, value):
        return self._pattern.search(value) is not None

    def __repr__(self):
        return f'{type(self).__name__}({self._pattern})'

    def __str__(self):
        return str(self._pattern.pattern)


class MustContain(DetailTableCellMatcher):
    def __init__(self, pattern_string):
        self._pattern = re.compile(pattern_string)


class MustMatch(DetailTableCellMatcher):
    def __init__(self, pattern_string):
        self._pattern = re.compile(pattern_string)


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
REGEX_LEGACY_BAD_CIPHERS = MustMatch(r'(IDEA|DES|RC4|NULL)')
REGEX_MODERN_BAD_CIPHERS = MustMatch(r'AES(128|256)-CCM')
REGEX_PHASE_OUT_CIPHERS = MustMatch(r'(DES.+CBC3|3DES.+CBC|AES(128|256)-(GCM-SHA(256|384)|SHA(256)?)).* \({}\)'.format(PHASE_OUT_TEXT))


# Some of the "mock" target servers are powered by OpenSSL server which cannot
# be configured to serve specific HTTP responses headers (e.g. HSTS) in
# combination with OCSP stapling, thus we have to accept these failures when
# using such a server.
class OpenSSLServerDomainConfig(DomainConfig):
    def __init__(self, test_id, domain, expected_warnings=None,
                 expected_failures=None, manual_cipher_checks=False):
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
                TESTS.TLS_CIPHER_SUITES, [[REGEX_PHASE_OUT_CIPHERS]])

        # Since we can't control the HTTP response headers produced by the
        # OpenSSL 'www' server that means that HTTP response header related
        # tests will fail. The HTTP security tests produce a warning when they
        # fail.
        self.expected_failures.setdefault(TESTS.HTTPS_HTTP_HSTS, ANY)
        for test in (
            TESTS.SECURITY_HTTP_REFERRER,
            TESTS.SECURITY_HTTP_XCONTYPE,
            TESTS.SECURITY_HTTP_XFRAME,
            TESTS.SECURITY_HTTP_XXSS
        ):
            self.expected_warnings.setdefault(test, ANY)


class PreTLS12DomainConfig(DomainConfig):
    def __init__(self, test_id, domain, expected_warnings=None,
            expected_failures=None, lang='en'):
        self._lang = lang
        super().__init__(test_id, domain,
            expected_warnings=expected_warnings,
            expected_failures=expected_failures)

    def override_defaults(self):
        if self._lang == 'en':
            test_id = TESTS.TLS_KEY_EXCHANGE
            phase_out_txt = PHASE_OUT_TEXT
        elif self._lang == 'nl':
            test_id = TESTS.TLS_KEY_EXCHANGE_NL
            phase_out_txt = PHASE_OUT_TEXT_NL
        else:
            raise ValueError()

        self.expected_warnings.setdefault(test_id, [
            [MustMatch(fr'(MD5|SHA1) \({phase_out_txt}\)')],
        ])


# Tests specifically intended to show that Internet.NL tests for compliance
# with the NCSC 2.0 guidelines.
ncsc_20_tests = [
    # The NaSSL LegacySslClient can connect to SSLv2 ONLY servers but only if
    # the  SSLV2 protocol is explicitly requested. The initial connection made
    # by Internet.NL doesn't request SSLV2 explicitly, instead it requests
    # SSLV23 which should connect to SSLv2 servers but appears to
    # fail to do so if the server _ONLY_ supports SSLv2. Currently the decision
    # is to leave Internet.NL as it is rather than add yet another connection
    # attempt with SSLv2 only, as the number of servers out there supporting
    # just SSLv2 is likely very low and because the generated report is still
    # red due to the failing "HTTPS available" test. So, we expect a "HTTPS
    # available" test failure, not a "TLS version" test failure.
    DomainConfig('NCSC20-Table1:SSL20',
        'ssl2only.test.nlnetlabs.tk',
        expected_failures={
            TESTS.IPV6_WEB_SAME_WEBSITE,
            TESTS.HTTPS_HTTP_HTTPS_AVAILABLE,
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
            TESTS.TLS_CIPHER_SUITES,
            TESTS.TLS_CIPHER_ORDER,
            TESTS.TLS_CLIENT_RENEG,
            TESTS.TLS_COMPRESSION,
            TESTS.TLS_KEY_EXCHANGE,
            TESTS.TLS_OCSP_STAPLING,
            TESTS.TLS_SECURE_RENEG,
            TESTS.TLS_VERSION,
            TESTS.TLS_ZERO_RTT,
            TESTS.SECURITY_HTTP_CSP,
            TESTS.SECURITY_HTTP_REFERRER,
            TESTS.SECURITY_HTTP_XCONTYPE,
            TESTS.SECURITY_HTTP_XFRAME,
            TESTS.SECURITY_HTTP_XXSS,
        }),

    # internet.nl cannot make SSLv3 connections so instead of failing because
    # of the insecure TLS version it fails because it cannot detect HTTPS
    # support at all.
    DomainConfig('NCSC20-Table1:SSL30',
        'ssl3only.test.nlnetlabs.tk',
        expected_failures={
            TESTS.TLS_VERSION,
            TESTS.TLS_CIPHER_SUITES,
            TESTS.TLS_CIPHER_ORDER,
            TESTS.TLS_CLIENT_RENEG,
            TESTS.TLS_SECURE_RENEG,
            TESTS.TLS_KEY_EXCHANGE,
        }),

    PreTLS12DomainConfig('NCSC20-Table1:TLS10',
        'tls10only.test.nlnetlabs.tk',
        expected_warnings={
            TESTS.TLS_VERSION: [
                [f'TLS 1.0 ({PHASE_OUT_TEXT})'],  # IPv6
                [f'TLS 1.0 ({PHASE_OUT_TEXT})'],  # IPv4
            ]
        }),

    PreTLS12DomainConfig('NCSC20-GuidelineB2-5:TLS10',
        'tls10onlyhonorclientcipherorder.test.nlnetlabs.tk',
        expected_warnings={
            TESTS.TLS_VERSION: [
                [f'TLS 1.0 ({PHASE_OUT_TEXT})'],  # IPv6
                [f'TLS 1.0 ({PHASE_OUT_TEXT})'],  # IPv4
            ]
        },
        expected_failures={
            TESTS.TLS_CIPHER_ORDER
        }),

    DomainConfig('NCSC20'
        '-Table12:TLS10',
        'tls10onlyinsecurereneg.test.nlnetlabs.tk',
        expected_warnings={
            TESTS.TLS_VERSION: [
                [f'TLS 1.0 ({PHASE_OUT_TEXT})'],  # IPv6
                [f'TLS 1.0 ({PHASE_OUT_TEXT})'],  # IPv4
            ]
        },
        expected_failures={
            TESTS.TLS_CIPHER_ORDER,
            TESTS.TLS_CIPHER_SUITES,
            TESTS.TLS_CLIENT_RENEG,
            TESTS.TLS_SECURE_RENEG,
            TESTS.TLS_KEY_EXCHANGE,
        }),

    PreTLS12DomainConfig('NCSC20-Table1:TLS11',
        'tls11only.test.nlnetlabs.tk',
        expected_warnings={
            TESTS.TLS_VERSION: [
                [f'TLS 1.1 ({PHASE_OUT_TEXT})'],  # IPv6
                [f'TLS 1.1 ({PHASE_OUT_TEXT})'],  # IPv4
            ],
        }),

    PreTLS12DomainConfig('NCSC20-Table1:TLS1011',
        'tls1011.test.nlnetlabs.tk',
        expected_warnings={
            TESTS.TLS_VERSION: [
                [f'TLS 1.1 ({PHASE_OUT_TEXT})'],  # IPv6
                [f'TLS 1.0 ({PHASE_OUT_TEXT})'],  # IPv6
                [f'TLS 1.1 ({PHASE_OUT_TEXT})'],  # IPv4
                [f'TLS 1.0 ({PHASE_OUT_TEXT})'],  # IPv4
            ],
        }),

    PreTLS12DomainConfig('NCSC20-Table1:TLS1112',
        'tls1112.test.nlnetlabs.tk',
        expected_warnings={
            TESTS.TLS_VERSION: [
                [f'TLS 1.1 ({PHASE_OUT_TEXT})'],  # IPv6
                [f'TLS 1.1 ({PHASE_OUT_TEXT})'],  # IPv4
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
            TESTS.TLS_CIPHER_SUITES,
            TESTS.TLS_CIPHER_ORDER,
            TESTS.TLS_CLIENT_RENEG,
            TESTS.TLS_COMPRESSION,
            TESTS.TLS_KEY_EXCHANGE,
            TESTS.TLS_OCSP_STAPLING,
            TESTS.TLS_SECURE_RENEG,
            TESTS.TLS_VERSION,
            TESTS.TLS_ZERO_RTT,
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
            TESTS.TLS_CIPHER_SUITES: [
                [REGEX_LEGACY_BAD_CIPHERS],  # matches all rows
            ]
        }),
    DomainConfig('NCSC20'
        '-Table1:TLS12'
        '-Table6:LegacyPhaseOutCiphers',
        'tls12onlylegacyphaseoutciphers.test.nlnetlabs.tk',
        expected_warnings={
            TESTS.TLS_CIPHER_SUITES: [
                [REGEX_PHASE_OUT_CIPHERS],  # matches all rows
            ]
        }),
    DomainConfig('NCSC20'
        '-Table1:TLS12'
        '-Table6:ModernPhaseOutCiphers',
        'tls12onlymodernphaseoutciphers.test.nlnetlabs.tk',
        expected_warnings={
            TESTS.TLS_CIPHER_SUITES: [
                [REGEX_PHASE_OUT_CIPHERS],  # matches all rows
            ],
        }),
    DomainConfig('NCSC20'
        '-Table1:TLS12'
        '-Table6:ModernBadCiphers',
        'tls12onlymodernbadciphers.test.nlnetlabs.tk',
        expected_failures={
            TESTS.TLS_CIPHER_SUITES: [
                [REGEX_MODERN_BAD_CIPHERS],  # matches all rows
            ],
        }),

    # 0-RTT is a TLS 1.3 feature so should not be tested.
    # Finite-field group ffdhe2048 is listed as 'phase out' by NCSC 2.0 and
    # so should result in a perfect score and a warning about the ff group.
    DomainConfig('NCSC20'
        '-Table1:TLS12'
        '-Table10:FFDHE2048',
        'tls12onlyffdhe2048.test.nlnetlabs.tk',
        expected_warnings={
            TESTS.TLS_KEY_EXCHANGE: [
                [MustMatch(fr'DH-FFDHE2048 \({PHASE_OUT_TEXT}\)')]
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
            TESTS.TLS_KEY_EXCHANGE: [
                ['DH-4096'],
                ['DH-4096'],
            ]
        }),

    DomainConfig('NCSC20'
        '-Table1:TLS12'
        '-Table1:TLS13'
        '-Table5:No',
        'tls1213nosha2.test.nlnetlabs.tk',
        expected_warnings={
            TESTS.TLS_KEY_EXCHANGE: [
                [f'SHA1 ({PHASE_OUT_TEXT})'],  # IPv6
                [f'SHA1 ({PHASE_OUT_TEXT})'],  # IPv4
            ]
        }),

    DomainConfig('NCSC20'
        '-Table11:TLS12'
        '-Table13:TLS12',
        'tls1213tlscompression.test.nlnetlabs.tk',
        expected_failures={
            TESTS.TLS_COMPRESSION
        }),

    # This website virtual host configuration deliberately does not do OCSP
    # stapling.
    DomainConfig('NCSC20'
        '-Table1:TLS1213'
        '-Table15:Off',
        'tls1213noocspstaple.test.nlnetlabs.tk',
        expected_passes={
            TESTS.TLS_OCSP_STAPLING: [
                ['no'],  # IPv6
                ['no'],  # IPv4
            ]
        },
        expected_score=PERFECT_SCORE),

    # This website virtual host configuration deliberately supports 0-RTT
    # Note: if NGINX hasn't already fetched the OCSP responder response it will
    # not staple the OCSP responder data in the response to us and this test
    # will fail. NGINX should be configured to serve OCSP responder data from
    # a file to avoid this issue.
    BadDomain('NCSC20'
        '-Table1:TLS13'
        '-Table14:On',
        'tls130rtt.test.nlnetlabs.tk',
        {TESTS.TLS_ZERO_RTT}),

    # This website virtual host configuration deliberately serves an OCSP
    # response that was obtained for a different domain/cert and so is invalid
    # for this domain/cert.
    BadDomain('NCSC20'
        '-Table1:TLS13'
        '-Table15:OnInvalid',
        'tls13invalidocsp.test.nlnetlabs.tk',
        expected_failures={
            TESTS.TLS_OCSP_STAPLING: [
                ['no'],  # IPv6
                ['no'],  # IPv4
            ]
        }),

    BadDomain('NCSC20-GuidelineB2-5:TLS13',
        'tls13onlyhonorclientcipherorder.test.nlnetlabs.tk',
        expected_failures={
            TESTS.TLS_CIPHER_ORDER
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
    PreTLS12DomainConfig('NCSC20-Table1:TLS10',
        'tls10only.test.nlnetlabs.tk',
        expected_warnings={
            TESTS.TLS_VERSION_NL: [
                [f'TLS 1.0 ({PHASE_OUT_TEXT_NL})'],  # IPv6
                [f'TLS 1.0 ({PHASE_OUT_TEXT_NL})'],  # IPv4
            ]
        },
        lang='nl'),
]


# The order of the ciphers in the tables below matches that of Appendix C of
# the NCSC "IT Security Guidelines for Transport Layer Security (TLS)" 2.0.
ncsc_20_good_ciphers = [
    ('TLS12', 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',       'ECDHE-ECDSA-AES256-GCM-SHA384'), # FAIL (wrong cipher)
    ('TLS12', 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256', 'ECDHE-ECDSA-CHACHA20-POLY1305'), # FAIL (wrong cipher)
    ('TLS12', 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',       'ECDHE-ECDSA-AES128-GCM-SHA256'), # FAIL (wrong cipher)
    ('TLS12', 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',         'ECDHE-RSA-AES256-GCM-SHA384'),
    ('TLS12', 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',   'ECDHE-RSA-CHACHA20-POLY1305'),
    ('TLS12', 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',         'ECDHE-RSA-AES128-GCM-SHA256'),
]

ncsc_20_sufficient_ciphers = [
    ('TLS12', 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',       'ECDHE-ECDSA-AES256-SHA384'),     # FAIL (wrong cipher)
    ('TLS12', 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',          'ECDHE-ECDSA-AES256-SHA'),        # FAIL (wrong cipher)
    ('TLS12', 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',       'ECDHE-ECDSA-AES128-SHA256'),     # FAIL (wrong cipher)
    ('TLS12', 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',          'ECDHE-ECDSA-AES128-SHA'),        # FAIL (wrong cipher)
    ('TLS12', 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',         'ECDHE-RSA-AES256-SHA384'),
    ('TLS12', 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',            'ECDHE-RSA-AES256-SHA'),
    ('TLS12', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',         'ECDHE-RSA-AES128-SHA256'),
    ('TLS12', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',            'ECDHE-RSA-AES128-SHA'),
    ('TLS12', 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',           'DHE-RSA-AES256-GCM-SHA384'),
    ('TLS12', 'TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256',     'DHE-RSA-CHACHA20-POLY1305'),     # FAIL (wrong cipher)
    ('TLS12', 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256',           'DHE-RSA-AES128-GCM-SHA256'),
    ('TLS12', 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256',           'DHE-RSA-AES256-SHA256'),
    ('TLS12', 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA',              'DHE-RSA-AES256-SHA'),
    ('TLS12', 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256',           'DHE-RSA-AES128-SHA256'),
    ('TLS12', 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA',              'DHE-RSA-AES128-SHA'),
]

ncsc_20_phaseout_ciphers = [
    ('TLS12', 'TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA',         'ECDHE-ECDSA-DES-CBC3-SHA'),
    ('TLS12', 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA',           'ECDHE-RSA-DES-CBC3-SHA'),        # FAIL (HTTPS available)
    ('TLS12', 'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA',             'EDH-RSA-DES-CBC3-SHA'),
    ('TLS12', 'TLS_RSA_WITH_AES_256_GCM_SHA384',               'AES256-GCM-SHA384'),
    ('TLS12', 'TLS_RSA_WITH_AES_128_GCM_SHA256',               'AES128-GCM-SHA256'),
    ('TLS12', 'TLS_RSA_WITH_AES_256_CBC_SHA256',               'AES256-SHA256'),
    ('TLS12', 'TLS_RSA_WITH_AES_256_CBC_SHA',                  'AES256-SHA'),
    ('TLS12', 'TLS_RSA_WITH_AES_128_CBC_SHA256',               'AES128-SHA256'),
    ('TLS12', 'TLS_RSA_WITH_AES_128_CBC_SHA',                  'AES128-SHA'),
    ('TLS12', 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',                 'DES-CBC3-SHA'),
]


mail_tests = [
    DomainConfig(
        'mail test', 'tls12only.test.nlnetlabs.tk',
        expected_warnings={
            TESTS.TLS_CLIENT_RENEG
        },
        expected_failures={
            TESTS.TLS_KEY_EXCHANGE,
        }
    ),

    pytest.param(DomainConfig(
        'mail test', 'tls13only.test.nlnetlabs.tk'),
        marks=pytest.mark.xfail),

    pytest.param(DomainConfig(
        'mail test', 'tls130rtt.test.nlnetlabs.tk'),
        marks=pytest.mark.xfail),
]


# Compare the test 'Technical details' table cells against expectations, if
# defined.
def check_table(selenium, expectation):
    for test_title, expected_details_table in expectation.items():
        if expected_details_table:
            regex_mode = False
            must_contain_mode = False
            expected_row = None

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
                    assert regex_mode is True, f"At row {i} in result table of test '{test_title}': table has more rows than expected, either use a regex to match all rows or define more expected rows"

                # for each column in the row:
                for j, col in enumerate(row):
                    expected_col = expected_row[j]

                    if isinstance(expected_col, DetailTableCellMatcher):
                        # compare the report table cell to the regular
                        # expression that the last expectation row contained:
                        if not regex_mode:
                            regex_mode = True
                            if isinstance(expected_col, MustContain):
                                must_contain_mode = True

                        matched = expected_col.matches(col)
                        if isinstance(expected_col, MustMatch):
                            assert matched, f"At row {i} col {j} in result table of test '{test_title}': cell value '{col}' does not match specified regex '{expected_col}'"
                        elif isinstance(expected_col, MustContain):
                            if matched:
                                return
                        else:
                            assert False, f"At row {i} col {j} in result table of test '{test_title}': expected value '{type(expected_col)}' must be one of type string, MustContain or MustMatch"
                    else:
                        # compare the report table cell to the expected cell at
                        # that position
                        assert col == expected_col

            # If we reach this point then either:
            #   - All cell values matched expectations
            assert not must_contain_mode, f"Result table of test '{test_title}' has no rows that match '{expected_col}'"


def assess_website(selenium, domain_config, lang='en'):
    run_assessment(selenium, domain_config, lang, mail=False)


def assess_mail_servers(selenium, domain_config, lang='en'):
    run_assessment(selenium, domain_config, lang, mail=True)


def run_assessment(selenium, domain_config, lang, mail=False):
    # Make it clear in the pytest output which website we were connecting to,
    # because when the domain is invalid the test output only shows the
    # /test-site/?invalid URL, not the URL of the site requested to be tested.
    if mail:
        print(f"Assessing mail servers @ '{domain_config.domain}' in language '{lang}'")
    else:
        print(f"Assessing website '{domain_config.domain}' in language '{lang}'")

    UX.submit_website_test_form(selenium, domain_config.domain, lang, mail)
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


def iana_cipher_to_target_server_fqdn(group, iana_cipher):
    ssl_version = iana_cipher[0]
    iana_cipher_name = iana_cipher[1]
    domain = 'test.nlnetlabs.tk'

    if 'ECDSA' in iana_cipher_name:
        # This cipher requires a special SSL certificate that contains an
        # elliptic curve ID. The FQDN was too long for the certificate creation
        # tooling so a wildcard cert for all 'ec' certificate using domains was
        # created and thus for this cert we need to adjust the target server
        # FQDN.
        domain = f'ec.{domain}'

    return f'{ssl_version.lower()}only{group}{iana_cipher_name.replace("_", "")}.{domain}'


def iana_cipher_id_generator(val):
    if isinstance(val, tuple):
        return '{}-{}'.format(
            val[0], val[1])


@pytest.mark.parametrize(
    'domain_config', ncsc_20_tests, ids=domainconfig_id_generator)
def test_ncsc_20(selenium, domain_config):
    assess_website(selenium, domain_config)


@pytest.mark.parametrize(
    'domain_config', other_tests, ids=domainconfig_id_generator)
def test_others(selenium, domain_config):
    assess_website(selenium, domain_config)


@pytest.mark.parametrize(
    'domain_config', nl_translation_tests, ids=domainconfig_id_generator)
def test_translations(selenium, domain_config):
    assess_website(selenium, domain_config, 'nl')


# Note: A temporary modification was made to Internet.NL to verify the exact
# cipher that is connected with even for good and sufficient ciphers, and all
# NCSC 2.0 good and sufficient cipher tests were seen to connect with the
# correct cipher. The change was not kept however because it required an
# additional database field that would never otherwise be used. Without the
# temporary modification this test can only verify that Internet.NL connects,
# but cannot verify whether the expected cipher was selected by the server.
@pytest.mark.parametrize(
    'iana_cipher', ncsc_20_good_ciphers, ids=iana_cipher_id_generator)
def test_ncsc_good_ciphers(selenium, iana_cipher):
    assess_website(selenium,
        GoodDomain('ncsc_good_ciphers',
            iana_cipher_to_target_server_fqdn('GOOD', iana_cipher)))


@pytest.mark.parametrize(
    'iana_cipher', ncsc_20_sufficient_ciphers, ids=iana_cipher_id_generator)
def test_ncsc_sufficient_ciphers(selenium, iana_cipher):
    assess_website(selenium,
        GoodDomain('ncsc_sufficient_ciphers',
            iana_cipher_to_target_server_fqdn('SUFFICIENT', iana_cipher)))


@pytest.mark.parametrize(
    'iana_cipher', ncsc_20_phaseout_ciphers, ids=iana_cipher_id_generator)
def test_ncsc_phaseout_ciphers(selenium, iana_cipher):
    openssl_cipher_name = iana_cipher[2]
    assess_website(selenium,
        DomainConfig('ncsc_phaseout_ciphers',
            iana_cipher_to_target_server_fqdn('PHASEOUT', iana_cipher),
            expected_warnings={
                TESTS.TLS_CIPHER_SUITES: [
                    [MustContain(fr'{openssl_cipher_name} \({PHASE_OUT_TEXT}\)')],
                ],
            }))


@pytest.mark.parametrize(
    'domain_config', mail_tests, ids=domainconfig_id_generator)
def test_mail(selenium, domain_config):
    assess_mail_servers(selenium, domain_config)
