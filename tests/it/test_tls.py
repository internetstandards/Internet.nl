import pytest
import re
import time
from helpers import DomainConfig, GoodDomain, BadDomain
from helpers import domainconfig_id_generator, TESTS, UX
from helpers import IMPERFECT_SCORE, PERFECT_SCORE
from helpers import INSUFFICIENT_TEXT, PHASE_OUT_TEXT, PHASE_OUT_TEXT_NL, ANY
from helpers import NOTTESTABLE_TEXT, NOTREACHABLE_TEXT
from selenium.common.exceptions import ElementNotInteractableException


class DetailTableCellMatcher:
    def __init__(self, pattern_string):
        self._pattern = re.compile(pattern_string)

    def matches(self, value):
        return self._pattern.search(value) is not None

    def __repr__(self):
        return f'{type(self).__name__}({self._pattern})'

    def __str__(self):
        return str(self._pattern.pattern)


class MustContain(DetailTableCellMatcher):
    pass


class MustMatch(DetailTableCellMatcher):
    pass


REGEX_LEGACY_BAD_CIPHERS = MustMatch(r'(IDEA|DES|RC4|NULL)')
REGEX_MODERN_BAD_CIPHERS = MustMatch(r'AES(128|256)-CCM')
REGEX_PHASE_OUT_CIPHERS = MustMatch(r'(DES.+CBC3|3DES.+CBC|AES(128|256)-(GCM-SHA(256|384)|SHA(256)?))')


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
                TESTS.TLS_CIPHER_SUITES, [
                    [REGEX_PHASE_OUT_CIPHERS, PHASE_OUT_TEXT],  # matches all rows
                ])

        # Since we can't control the HTTP response headers produced by the
        # OpenSSL 'www' server that means that HTTP response header related
        # tests will fail. The HTTP security tests produce a warning when they
        # fail.
        self.expected_failures.setdefault(TESTS.HTTPS_HTTP_HSTS, ANY)
        for test in (
            TESTS.SECURITY_HTTP_REFERRER,
            TESTS.SECURITY_HTTP_XCONTYPE,
            TESTS.SECURITY_HTTP_XFRAME,
            TESTS.SECURITY_HTTP_CSP,
        ):
            self.expected_warnings.setdefault(test, ANY)


class PreTLS13DomainConfig(DomainConfig):
    def __init__(self, test_id, domain, expected_warnings=None,
            expected_failures=None, expected_info=None, lang='en'):
        self._lang = lang
        super().__init__(test_id, domain,
            expected_warnings=expected_warnings,
            expected_failures=expected_failures,
            expected_info=expected_info)


class PreTLS12DomainConfig(DomainConfig):
    def __init__(self, test_id, domain, expected_warnings=None,
            expected_failures=None, expected_info=None, lang='en'):
        self._lang = lang
        super().__init__(test_id, domain,
            expected_warnings=expected_warnings,
            expected_failures=expected_failures,
            expected_info=expected_info)

    def override_defaults(self):
        if self._lang == 'en':
            hf_test_id = TESTS.TLS_HASH_FUNC
            zrtt_test_id = TESTS.TLS_ZERO_RTT
        elif self._lang == 'nl':
            hf_test_id = TESTS.TLS_HASH_FUNC_NL
            zrtt_test_id = TESTS.TLS_ZERO_RTT_NL
        else:
            raise ValueError()

        self.expected_warnings.setdefault(hf_test_id, ANY)


class PostfixTLS12Config(DomainConfig):
    def override_defaults(self):
        self.expected_failures.setdefault(TESTS.TLS_KEY_EXCHANGE, ANY)
        # self.expected_info.setdefault(TESTS.TLS_OCSP_STAPLING, [['no']])
        self.expected_info.setdefault(TESTS.DANE_ROLLOVER_SCHEME, ANY)


class PostfixTLS13Config(DomainConfig):
    def override_defaults(self):
        # self.expected_failures.setdefault(TESTS.TLS_CIPHER_ORDER, ANY)
        # self.expected_info.setdefault(TESTS.TLS_OCSP_STAPLING, [['no']])
        self.expected_info.setdefault(TESTS.DANE_ROLLOVER_SCHEME, ANY)


# Tests specifically intended to show that Internet.NL tests for compliance
# with the NCSC 2.0 guidelines.
ncsc_20_tests = [
    DomainConfig('NCSC20-Table1:SSL20',
        'ssl2only.test.nlnetlabs.tk',
        expected_failures={
            TESTS.HTTPS_HTTP_HSTS,
            TESTS.TLS_VERSION,
            TESTS.TLS_CIPHER_SUITES,
            TESTS.TLS_SECURE_RENEG,
        },
        expected_warnings={
            TESTS.TLS_HASH_FUNC,
            TESTS.SECURITY_HTTP_CSP,
            TESTS.SECURITY_HTTP_REFERRER,
            TESTS.SECURITY_HTTP_XCONTYPE,
        },
        expected_info={
            TESTS.TLS_OCSP_STAPLING,
            TESTS.DANE_EXISTS,
            TESTS.SECURITY_HTTP_XFRAME,
        },
        expected_not_tested={
            TESTS.DANE_VALID,
            TESTS.HTTPS_CERT_DOMAIN,
            TESTS.HTTPS_CERT_PUBKEY,
            TESTS.HTTPS_CERT_SIG,
            TESTS.HTTPS_CERT_TRUST,
        }),

    # internet.nl cannot make SSLv3 connections so instead of failing because
    # of the insecure TLS version it fails because it cannot detect HTTPS
    # support at all.
    PreTLS12DomainConfig('NCSC20-Table1:SSL30',
        'ssl3only.test.nlnetlabs.tk',
        expected_failures={
            TESTS.TLS_CIPHER_ORDER,
            TESTS.TLS_CIPHER_SUITES,
            TESTS.TLS_KEY_EXCHANGE,
            TESTS.TLS_SECURE_RENEG,
            TESTS.TLS_VERSION,
        },
        expected_info={
            TESTS.TLS_OCSP_STAPLING,
            TESTS.TLS_CLIENT_RENEG,
        }),

    PreTLS12DomainConfig('NCSC20-Table1:TLS10',
        'tls10only.test.nlnetlabs.tk',
        expected_warnings={
            TESTS.TLS_VERSION: [
                ['TLS 1.0', PHASE_OUT_TEXT],  # IPv6/IPv4
                ['TLS 1.0', PHASE_OUT_TEXT],  # IPv6/IPv4
            ]
        }),

    PreTLS12DomainConfig('NCSC20-GuidelineB2-5:TLS10',
        'tls10onlyhonorclientcipherorder.test.nlnetlabs.tk',
        expected_warnings={
            TESTS.TLS_VERSION: [
                ['TLS 1.0', PHASE_OUT_TEXT],  # IPv6/IPv4
                ['TLS 1.0', PHASE_OUT_TEXT],  # IPv6/IPv4
            ]
        },
        expected_failures={
            TESTS.TLS_CIPHER_ORDER
        }),

    PreTLS12DomainConfig('NCSC20'
        '-Table12:TLS10',
        'tls10onlyinsecurereneg.test.nlnetlabs.tk',
        expected_warnings={
            TESTS.TLS_VERSION: [
                ['TLS 1.0', PHASE_OUT_TEXT],  # IPv6/IPv4
                ['TLS 1.0', PHASE_OUT_TEXT],  # IPv6/IPv4
            ],
        },
        expected_failures={
            TESTS.TLS_CIPHER_SUITES,
            TESTS.TLS_CIPHER_ORDER,
            TESTS.TLS_KEY_EXCHANGE,
            TESTS.TLS_SECURE_RENEG,
        },
        expected_info={
            TESTS.TLS_OCSP_STAPLING,
            TESTS.TLS_CLIENT_RENEG,
        }),

    PreTLS12DomainConfig('NCSC20-Table1:TLS11',
        'tls11only.test.nlnetlabs.tk',
        expected_warnings={
            TESTS.TLS_VERSION: [
                ['TLS 1.1', PHASE_OUT_TEXT],  # IPv6/IPv4
                ['TLS 1.1', PHASE_OUT_TEXT],  # IPv6/IPv4
            ],
        }),

    PreTLS12DomainConfig('NCSC20-Table1:TLS1011',
        'tls1011.test.nlnetlabs.tk',
        expected_warnings={
            TESTS.TLS_VERSION: [
                ['TLS 1.1', PHASE_OUT_TEXT],  # IPv6/IPv4
                ['TLS 1.0', PHASE_OUT_TEXT],  # IPv6/IPv4
                ['TLS 1.1', PHASE_OUT_TEXT],  # IPv6/IPv4
                ['TLS 1.0', PHASE_OUT_TEXT],  # IPv6/IPv4
            ],
        }),

    PreTLS13DomainConfig('NCSC20-Table1:TLS1112',
        'tls1112.test.nlnetlabs.tk',
        expected_warnings={
            TESTS.TLS_VERSION: [
                ['TLS 1.1', PHASE_OUT_TEXT],  # IPv6/IPv4
                ['TLS 1.1', PHASE_OUT_TEXT],  # IPv6/IPv4
            ]
        }),

    PreTLS13DomainConfig('NCSC20'
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
        },
        expected_info={
            TESTS.DANE_EXISTS
        }),

    DomainConfig('NCSC20-Table1:None',
        'nossl.test.nlnetlabs.tk',
        expected_error={
            TESTS.HTTPS_HTTP_HTTPS_AVAILABLE: [
                [NOTREACHABLE_TEXT],  # IPv6/IPv4
                [NOTREACHABLE_TEXT],  # IPv6/IPv4
            ]
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
            TESTS.SECURITY_HTTP_CSP,
            TESTS.SECURITY_HTTP_REFERRER,
            TESTS.SECURITY_HTTP_XCONTYPE,
            TESTS.SECURITY_HTTP_XFRAME,
            TESTS.TLS_CIPHER_ORDER,
            TESTS.TLS_CIPHER_SUITES,
            TESTS.TLS_CLIENT_RENEG,
            TESTS.TLS_COMPRESSION,
            TESTS.TLS_HASH_FUNC,
            TESTS.TLS_KEY_EXCHANGE,
            TESTS.TLS_OCSP_STAPLING,
            TESTS.TLS_SECURE_RENEG,
            TESTS.TLS_VERSION,
            TESTS.TLS_ZERO_RTT,
        }),

    PreTLS13DomainConfig('NCSC20-GuidelineB2-5:TLS10',
        'tls12onlynotsecurityorder.test.nlnetlabs.tk',
        expected_failures={
            TESTS.TLS_CIPHER_SUITES,
            TESTS.TLS_CIPHER_ORDER,
        }),

    # Prescribed ordering is now disabled.
    # This will be marked as skipped in test_ncsc_20().
    PreTLS13DomainConfig('NCSC20-GuidelineB2-5:TLS10',
        'tls12onlynotprescribedorder1.test.nlnetlabs.tk',
        expected_warnings={
            TESTS.TLS_CIPHER_ORDER: [
                [MustMatch(r'.+'), ''],   # IPv6/IPv4
                [MustMatch(r'.+'), '1'],  # IPv6/IPv4
                [MustMatch(r'.+'), ''],   # IPv6/IPv4
                [MustMatch(r'.+'), '1'],  # IPv6/IPv4
            ]
        }),

    # Prescribed ordering is now disabled.
    # This will be marked as skipped in test_ncsc_20().
    PreTLS13DomainConfig('NCSC20-GuidelineB2-5:TLS10',
        'tls12onlynotprescribedorder4.test.nlnetlabs.tk',
        expected_warnings={
            TESTS.TLS_CIPHER_ORDER: [
                [MustMatch(r'.+'), ''],   # IPv6/IPv4
                [MustMatch(r'.+'), '4'],  # IPv6/IPv4
                [MustMatch(r'.+'), ''],   # IPv6/IPv4
                [MustMatch(r'.+'), '4'],  # IPv6/IPv4
            ]
        }),

    # With PRIORITIZE_CHACHA this now does not fail; CHACHA is ignored for
    # order. This will be marked as skipped in test_ncsc_20().
    PreTLS13DomainConfig('NCSC20-GuidelineB2-5:TLS10',
        'tls12onlyphaseoutorder.test.nlnetlabs.tk',
        expected_warnings={
            TESTS.TLS_CIPHER_SUITES,
        },
        expected_failures={
            TESTS.TLS_CIPHER_ORDER: [
                [MustMatch(r'.+'), ''],   # IPv6/IPv4
                [MustMatch(r'.+'), 'None'],  # IPv6/IPv4
                [MustMatch(r'.+'), ''],   # IPv6/IPv4
                [MustMatch(r'.+'), 'None'],  # IPv6/IPv4
            ]
        }),

    PreTLS13DomainConfig('NCSC20'
        '-Table1:TLS12'
        '-Table6:LegacyBadCiphers',
        'tls12onlylegacybadciphers.test.nlnetlabs.tk',
        expected_failures={
            TESTS.TLS_CIPHER_SUITES: [
                [REGEX_LEGACY_BAD_CIPHERS, INSUFFICIENT_TEXT],  # matches all rows
            ],
            TESTS.TLS_CIPHER_ORDER: [],
        }),

    PreTLS13DomainConfig('NCSC20'
        '-Table1:TLS12'
        '-Table6:LegacyPhaseOutCiphers',
        'tls12onlylegacyphaseoutciphers.test.nlnetlabs.tk',
        expected_warnings={
            TESTS.TLS_CIPHER_SUITES: [
                [REGEX_PHASE_OUT_CIPHERS, PHASE_OUT_TEXT],  # matches all rows
            ]
        }),
    PreTLS13DomainConfig('NCSC20'
        '-Table1:TLS12'
        '-Table6:ModernBadCiphers',
        'tls12onlymodernbadciphers.test.nlnetlabs.tk',
        expected_failures={
            TESTS.TLS_CIPHER_SUITES: [
                [REGEX_MODERN_BAD_CIPHERS, INSUFFICIENT_TEXT],  # matches all rows
            ]
        }),
    PreTLS13DomainConfig('NCSC20'
        '-Table1:TLS12'
        '-Table6:ModernPhaseOutCiphers',
        'tls12onlymodernphaseoutciphers.test.nlnetlabs.tk',
        expected_warnings={
            TESTS.TLS_CIPHER_SUITES: [
                [REGEX_PHASE_OUT_CIPHERS, PHASE_OUT_TEXT],  # matches all rows
            ],
        },
        expected_info={
            TESTS.TLS_HASH_FUNC: [
                [MustMatch('not applicable')]
            ]
        }),

    # 0-RTT is a TLS 1.3 feature so should not be tested.
    # Finite-field group ffdhe2048 is listed as 'phase out' by NCSC 2.0 and
    # so should result in a perfect score and a warning about the ff group.
    PreTLS13DomainConfig('NCSC20'
        '-Table1:TLS12'
        '-Table10:FFDHE2048',
        'tls12onlyffdhe2048.test.nlnetlabs.tk',
        expected_warnings={
            TESTS.TLS_KEY_EXCHANGE: [
                ['DH-2048', PHASE_OUT_TEXT],  # IPv6/IPv4
                ['DH-2048', PHASE_OUT_TEXT],  # IPv6/IPv4
            ]
        }),

    PreTLS13DomainConfig('NCSC20'
        '-Table1:TLS12'
        '-Table10:FFDHE3072',
        'tls12onlyffdhe3072.test.nlnetlabs.tk'),

    # This domain doesn't use an NCSC 2.0 approved DH finite-field group.
    PreTLS13DomainConfig('NCSC20'
        '-Table1:TLS12'
        '-Table10:OtherGroups',
        'tls12onlyffother.test.nlnetlabs.tk',
        expected_failures={
            TESTS.TLS_KEY_EXCHANGE: [
                ['DH-4096', INSUFFICIENT_TEXT], # IPv6/IPv4
                ['DH-4096', INSUFFICIENT_TEXT], # IPv6/IPv4
            ]
        }),

    # This domain uses DH parameters that tripped a bug in Internet.NL because
    # it expected the generator to be a small integer value reported by NaSSL
    # as "2 (0x2)" but in fact NaSSL reports this long generator value as
    # "0x...", which being base 16 broke the base 10 string to int conversion.
    PreTLS13DomainConfig('NCSC20'
        '-Table1:TLS12'
        '-BUG:LongGenerator',
        'tls12onlydhlongg.test.nlnetlabs.tk',
        expected_failures={
            TESTS.TLS_KEY_EXCHANGE: [
                ['DH-1024', INSUFFICIENT_TEXT], # IPv6/IPv4
                ['DH-1024', INSUFFICIENT_TEXT], # IPv6/IPv4
            ]
        }),

    # Even though the server below supports TLS 1.3, in TLS 1.3 "Legacy
    # algorithms" "specifically SHA-1" "are not defined for use in signed TLS
    # handshake messages" and so we cannot connect with TLS 1.3 to this server
    # which lacks SHA2 and thus cannot test for 0-RTT support. See:
    #   "Legacy Algorithms" under "4.2.3. Signature Algorithms" of RFC-8446
    #   https://tools.ietf.org/html/rfc8446#section-4.2.3
    DomainConfig('NCSC20'
        '-Table1:TLS12'
        '-Table1:TLS13'
        '-Table5:No',
        'tls1213nosha2.test.nlnetlabs.tk',
        expected_warnings={
            TESTS.TLS_HASH_FUNC: [
                ['no'],  # IPv6/IPv4
                ['no'],  # IPv6/IPv4
            ]
        }),

    DomainConfig('NCSC20'
        '-Table1:TLS12'
        '-Table1:TLS13'
        '-Table6:ModernPhaseOutCiphers',
        'tls1213modernphaseoutciphers.test.nlnetlabs.tk',
        expected_warnings={
            TESTS.TLS_CIPHER_SUITES: [
                [REGEX_PHASE_OUT_CIPHERS, PHASE_OUT_TEXT],  # matches all rows
            ]
        },
        expected_info={
            TESTS.TLS_HASH_FUNC: [
                [MustMatch('not applicable')]
            ]
        }),

    PreTLS13DomainConfig('NCSC20'
        '-Table11:TLS12'
        '-Table13:TLS12',
        'tls1213tlscompression.test.nlnetlabs.tk',
        expected_failures={
            TESTS.TLS_COMPRESSION
        }),

    GoodDomain('NCSC20'
        '-Table1:TLS13'
        '-Table14:Off',
        'tls13only.test.nlnetlabs.tk'),

    # This website virtual host configuration deliberately does not do OCSP
    # stapling.
    DomainConfig('NCSC20'
        '-Table1:TLS1213'
        '-Table15:Off',
        'tls1213noocspstaple.test.nlnetlabs.tk',
        expected_info={
            TESTS.TLS_OCSP_STAPLING: [
                ['no'],  # IPv6/IPv4
                ['no'],  # IPv6/IPv4
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
    DomainConfig('NCSC20'
        '-Table1:TLS13'
        '-Table15:OnInvalid',
        'tls13invalidocsp.test.nlnetlabs.tk',
        expected_warnings={
            TESTS.TLS_OCSP_STAPLING: [
                ['no'],  # IPv6/IPv4
                ['no'],  # IPv6/IPv4
            ]
        }),

    # Supporting only GOOD ciphers (like TLS1.3 only) should
    # pass the cipher order test.
    GoodDomain('NCSC20-GuidelineB2-5:TLS13',
        'tls13onlyhonorclientcipherorder.test.nlnetlabs.tk'),
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
                ['max-age=1000; includeSubdomains;'],  # IPv6/IPv4
                ['max-age=1000; includeSubdomains;']   # IPv6/IPv4
            ]
        }),

    # This domain deliberately has no server listening on ipv6
    DomainConfig('IPV6:NONE',
        'tls13ipv4only.test.nlnetlabs.tk',
        expected_error={
            TESTS.HTTPS_HTTP_HTTPS_AVAILABLE: [
                [MustMatch(fr'({NOTREACHABLE_TEXT}|yes)')],  # IPv6/IPv4
                [MustMatch(fr'({NOTREACHABLE_TEXT}|yes)')],  # IPv6/IPv4
            ]
        },
        expected_failures={
            TESTS.IPV6_WEB_REACHABILITY,
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
            TESTS.IPV6_WEB_SAME_WEBSITE,
            TESTS.SECURITY_HTTP_CSP,
            TESTS.SECURITY_HTTP_REFERRER,
            TESTS.SECURITY_HTTP_XCONTYPE,
            TESTS.SECURITY_HTTP_XFRAME,
            TESTS.TLS_CIPHER_ORDER,
            TESTS.TLS_CIPHER_SUITES,
            TESTS.TLS_CLIENT_RENEG,
            TESTS.TLS_COMPRESSION,
            TESTS.TLS_HASH_FUNC,
            TESTS.TLS_KEY_EXCHANGE,
            TESTS.TLS_OCSP_STAPLING,
            TESTS.TLS_SECURE_RENEG,
            TESTS.TLS_VERSION,
            TESTS.TLS_ZERO_RTT,
        }),

    # This domain deliberately lacks an IPV6 AAAA record in DNS
    DomainConfig('IPV6:NONE',
        'tls13ipv4onlynoipv6.test.nlnetlabs.tk',
        expected_failures={
            TESTS.IPV6_WEB_ADDRESS
        },
        expected_not_tested={
            TESTS.IPV6_WEB_REACHABILITY,
            TESTS.IPV6_WEB_SAME_WEBSITE,
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
                ['TLS 1.0', PHASE_OUT_TEXT_NL],  # IPv6/IPv4
                ['TLS 1.0', PHASE_OUT_TEXT_NL],  # IPv6/IPv4
            ]
        },
        lang='nl'),
]


# The order of the ciphers in the tables below matches that of Appendix C of
# the NCSC "IT Security Guidelines for Transport Layer Security (TLS)" 2.0.
# Columns:
#   1: TLS protocol version offered by the test target server for this cipher
#        Used to construct the integration test target server FQDN
#   2: IANA cipher name
#   3: OpenSSL cipher name
ncsc_20_good_ciphers = [
    ('TLS12', 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',       'ECDHE-ECDSA-AES256-GCM-SHA384'),
    ('TLS12', 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256', 'ECDHE-ECDSA-CHACHA20-POLY1305'),
    ('TLS12', 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',       'ECDHE-ECDSA-AES128-GCM-SHA256'),
    ('TLS12', 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',         'ECDHE-RSA-AES256-GCM-SHA384'),
    ('TLS12', 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',   'ECDHE-RSA-CHACHA20-POLY1305'),
    ('TLS12', 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',         'ECDHE-RSA-AES128-GCM-SHA256'),
]

ncsc_20_sufficient_ciphers = [
    ('TLS12', 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',       'ECDHE-ECDSA-AES256-SHA384'),
    ('TLS12', 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',          'ECDHE-ECDSA-AES256-SHA'),
    ('TLS12', 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',       'ECDHE-ECDSA-AES128-SHA256'),
    ('TLS12', 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',          'ECDHE-ECDSA-AES128-SHA'),
    ('TLS12', 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',         'ECDHE-RSA-AES256-SHA384'),
    ('TLS12', 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',            'ECDHE-RSA-AES256-SHA'),
    ('TLS12', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',         'ECDHE-RSA-AES128-SHA256'),
    ('TLS12', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',            'ECDHE-RSA-AES128-SHA'),
    ('TLS12', 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',           'DHE-RSA-AES256-GCM-SHA384'),
    ('TLS12', 'TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256',     'DHE-RSA-CHACHA20-POLY1305'),
    ('TLS12', 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256',           'DHE-RSA-AES128-GCM-SHA256'),
    ('TLS12', 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256',           'DHE-RSA-AES256-SHA256'),
    ('TLS12', 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA',              'DHE-RSA-AES256-SHA'),
    ('TLS12', 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256',           'DHE-RSA-AES128-SHA256'),
    ('TLS12', 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA',              'DHE-RSA-AES128-SHA'),
]

# The next table has a fourth column:
#   4: SHA2 hash functions supported:
#        True  - yes
#        False - no
#        None  - not applicable (no hash function used with this cipher)
ncsc_20_phaseout_ciphers = [
    ('TLS12', 'TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA',         'ECDHE-ECDSA-DES-CBC3-SHA',  False),
    ('TLS12', 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA',           'ECDHE-RSA-DES-CBC3-SHA',    True),
    ('TLS12', 'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA',             'DHE-RSA-DES-CBC3-SHA',      True),
    ('TLS12', 'TLS_RSA_WITH_AES_256_GCM_SHA384',               'AES256-GCM-SHA384',         None),
    ('TLS12', 'TLS_RSA_WITH_AES_128_GCM_SHA256',               'AES128-GCM-SHA256',         None),
    ('TLS12', 'TLS_RSA_WITH_AES_256_CBC_SHA256',               'AES256-SHA256',             None),
    ('TLS12', 'TLS_RSA_WITH_AES_256_CBC_SHA',                  'AES256-SHA',                None),
    ('TLS12', 'TLS_RSA_WITH_AES_128_CBC_SHA256',               'AES128-SHA256',             None),
    ('TLS12', 'TLS_RSA_WITH_AES_128_CBC_SHA',                  'AES128-SHA',                None),
    ('TLS12', 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',                 'DES-CBC3-SHA',              None),
]


mail_tests = [
    PostfixTLS12Config(
        'mail test', 'tls12only.test.nlnetlabs.tk',
        expected_info={
            TESTS.TLS_CLIENT_RENEG
        }),

    PostfixTLS12Config(
        'mail test', 'tls1213prioritizechacha.test.nlnetlabs.tk'),

    DomainConfig(
        'mail test', 'tls12onlynoip.test.nlnetlabs.tk',
        expected_error={
            TESTS.STARTTLS_AVAILABLE: [
                [NOTREACHABLE_TEXT],  # IPv6/IPv4
            ]
        },
        expected_failures={
            TESTS.IPV6_MAIL_ADDRESS,
        },
        expected_not_tested={
            TESTS.IPV6_MAIL_REACHABILITY,
            TESTS.DANE_EXISTS,
            TESTS.DANE_VALID,
            TESTS.DANE_ROLLOVER_SCHEME,
            TESTS.TLS_CIPHER_SUITES,
            TESTS.TLS_CIPHER_ORDER,
            TESTS.TLS_CLIENT_RENEG,
            TESTS.TLS_COMPRESSION,
            TESTS.TLS_KEY_EXCHANGE,
            TESTS.TLS_SECURE_RENEG,
            TESTS.TLS_VERSION,
            TESTS.TLS_ZERO_RTT,
            TESTS.TLS_HASH_FUNC,
            TESTS.HTTPS_CERT_DOMAIN,
            TESTS.HTTPS_CERT_PUBKEY,
            TESTS.HTTPS_CERT_SIG,
            TESTS.HTTPS_CERT_TRUST
        }),

    PostfixTLS13Config(
        'mail', 'tls13ipv4only.test.nlnetlabs.tk',
        expected_failures={
            TESTS.IPV6_MAIL_REACHABILITY
        }),

    PostfixTLS13Config(
        'mail', 'tls13ipv6onlynoipv4.test.nlnetlabs.tk',),

    PostfixTLS13Config(
        'mail', 'tls13ipv4onlynoipv6.test.nlnetlabs.tk',
        expected_failures={
            TESTS.IPV6_MAIL_ADDRESS,
        },
        expected_not_tested={
            TESTS.IPV6_MAIL_REACHABILITY
        }),

    PostfixTLS13Config(
        'mail test', 'tls13only.test.nlnetlabs.tk'),

    PostfixTLS13Config(
        'mail test', 'tls130rtt.test.nlnetlabs.tk'),
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


def assess_website(selenium, domain_config, lang='en', base_urls=None, request=None):
    run_assessment(selenium, domain_config, lang, mail=False, base_urls=base_urls, request=request)


def assess_mail_servers(selenium, domain_config, lang='en', base_urls=None, request=None):
    run_assessment(selenium, domain_config, lang, mail=True, base_urls=base_urls, request=request)


def run_assessment(selenium, domain_config, lang, mail=False, base_urls=None, request=None):
    # Make it clear in the pytest output which website we were connecting to,
    # because when the domain is invalid the test output only shows the
    # /test-site/?invalid URL, not the URL of the site requested to be tested.
    if mail:
        print(f"Assessing mail servers @ '{domain_config.domain}' in language '{lang}'")
    else:
        print(f"Assessing website '{domain_config.domain}' in language '{lang}'")

    base_urls = base_urls if base_urls else [None]
    compare_mode = True if len(base_urls) > 1 else False

    if request:
        request.node._batch = True
        request.node._fqdn = domain_config.domain
        request.node._score = list()
        request.node._subresults = list()
        request.node._failures = list()
        request.node._warnings = list()

    if len(base_urls) > 2:
        raise NotImplementedError()

    total_score = 0
    for idx, this_base_url in enumerate(base_urls):
        print(f"Assessing using instance: {this_base_url}")
        UX.submit_website_test_form(selenium, domain_config.domain, lang, mail, base_url=this_base_url)
        UX.wait_for_test_to_start(selenium, domain_config.domain)
        UX.wait_for_test_to_complete(selenium)
        while True:
            try:
                UX.open_report_detail_sections(selenium)
                break
            except ElementNotInteractableException:
                print('UX not ready, waiting...')
                time.sleep(1)

        failed_tests = UX.get_failed_tests(selenium)
        warning_tests = UX.get_warning_tests(selenium)
        info_tests = UX.get_info_tests(selenium)
        nottested_tests = UX.get_nottested_tests(selenium)
        error_tests = UX.get_error_tests(selenium)
        passed_tests = UX.get_passed_tests(selenium)

        score_as_percentage_str = UX.get_score(selenium)
        score_as_int = int(score_as_percentage_str.strip('%'))

        if request:
            subresults = dict()
            subresults.update({k: 'x' for k in failed_tests})
            subresults.update({k: '!' for k in warning_tests})
            subresults.update({k: '.' for k in info_tests})
            subresults.update({k: '_' for k in nottested_tests})
            subresults.update({k: '%' for k in error_tests})
            subresults.update({k: '/' for k in passed_tests})
            request.node._score.append(score_as_int)
            request.node._subresults.append(subresults)

        if compare_mode:
            total_score += score_as_int
            if request:
                if idx == 0:
                    last_failed_tests = failed_tests
                    last_warning_tests = warning_tests
                elif idx == 1:
                    request.node._failures = sorted(set(failed_tests) - set(last_failed_tests))
                    request.node._warnings = sorted(set(warning_tests) - set(last_warning_tests))
        else:
            if request:
                request.node._failures = failed_tests
                request.node._warnings = warning_tests

            assert (failed_tests == set(domain_config.expected_failures.keys()))
            assert (warning_tests == set(domain_config.expected_warnings.keys()))
            assert (info_tests == set(domain_config.expected_info.keys()))
            assert (nottested_tests == set(domain_config.expected_not_tested.keys()))
            assert (error_tests == set(domain_config.expected_error.keys()))

            check_table(selenium, domain_config.expected_failures)
            check_table(selenium, domain_config.expected_not_tested)
            check_table(selenium, domain_config.expected_error)
            check_table(selenium, domain_config.expected_info)
            check_table(selenium, domain_config.expected_warnings)
            check_table(selenium, domain_config.expected_passes)

            if domain_config.expected_score:
                if domain_config.expected_score == IMPERFECT_SCORE:
                    assert score_as_int > 0 and score_as_int < 100
                else:
                    assert score_as_percentage_str == domain_config.expected_score

    if compare_mode:
        assert total_score == 200


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

    return f'{ssl_version}only{group}{iana_cipher_name.replace("_", "")}.{domain}'.lower()


def iana_cipher_id_generator(val):
    if isinstance(val, tuple):
        return '{}-{}-{}'.format(
            val[0], val[1], val[2])


@pytest.mark.parametrize(
    'domain_config', ncsc_20_tests, ids=domainconfig_id_generator)
def test_ncsc_20(selenium, domain_config):
    if domain_config.domain == 'tls12onlyphaseoutorder.test.nlnetlabs.tk':
        pytest.skip("Test not vaid since PRIORITIZE_CHACHA support")
    if domain_config.domain in [
            'tls12onlynotprescribedorder4.test.nlnetlabs.tk',
            'tls12onlynotprescribedorder1.test.nlnetlabs.tk',
            ]:
        pytest.skip("Prescribed order is now disabled")
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
        PreTLS13DomainConfig('ncsc_good_ciphers',
            iana_cipher_to_target_server_fqdn('GOOD', iana_cipher)))


@pytest.mark.parametrize(
    'iana_cipher', ncsc_20_sufficient_ciphers, ids=iana_cipher_id_generator)
def test_ncsc_sufficient_ciphers(selenium, iana_cipher):
    assess_website(selenium,
        PreTLS13DomainConfig('ncsc_sufficient_ciphers',
            iana_cipher_to_target_server_fqdn('SUFFICIENT', iana_cipher)))


@pytest.mark.parametrize(
    'iana_cipher', ncsc_20_phaseout_ciphers, ids=iana_cipher_id_generator)
def test_ncsc_phaseout_ciphers(selenium, iana_cipher):
    openssl_cipher_name = iana_cipher[2]
    ssh2_hash_function_supported = iana_cipher[3]
    if openssl_cipher_name == 'DHE-RSA-DES-CBC3-SHA':
        # The webserver uses both DHE-RSA-DES-CBC3-SHA and EDH-RSA-DES-CBC3-SHA
        # so the compaarison fails.
        expected_warnings = {
            TESTS.TLS_CIPHER_SUITES,
        }
    else:
        expected_warnings = {
            TESTS.TLS_CIPHER_SUITES: [
                [openssl_cipher_name, PHASE_OUT_TEXT],  # IPv6/IPv4
                [openssl_cipher_name, PHASE_OUT_TEXT],  # IPv6/IPv4
            ]
        }

    domain_config = PreTLS13DomainConfig('ncsc_phaseout_ciphers',
        iana_cipher_to_target_server_fqdn('PHASEOUT', iana_cipher),
        expected_warnings=expected_warnings)

    if ssh2_hash_function_supported is False:
        domain_config.expected_warnings[TESTS.TLS_HASH_FUNC] = [
            [MustMatch('no')]
        ]
    elif ssh2_hash_function_supported is None:
        domain_config.expected_info[TESTS.TLS_HASH_FUNC] = [
            [MustMatch('not applicable')]
        ]

    assess_website(selenium, domain_config)


@pytest.mark.parametrize(
    'domain_config', mail_tests, ids=domainconfig_id_generator)
def test_mail(selenium, domain_config):
    assess_mail_servers(selenium, domain_config)


# 'parametrized' by conftest.py::pytest_generate_tests()
def test_batch_web_domains(request, selenium, batch_base_urls, batch_domain):
    assess_website(
        selenium,
        GoodDomain('batch_domain', batch_domain),
        base_urls=batch_base_urls,
        request=request)


# 'parametrized' by conftest.py::pytest_generate_tests()
def test_batch_mail_domains(request, selenium, batch_base_urls, batch_domain):
    assess_mail_servers(
        selenium,
        GoodDomain('batch_domain', batch_domain),
        base_urls=batch_base_urls,
        request=request)
