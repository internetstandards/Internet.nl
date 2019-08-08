# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
from binascii import hexlify
from collections import namedtuple
import csv
import errno
import http.client
import logging
import re
import socket
import ssl
import time
from enum import Enum
from timeit import default_timer as timer

from celery import shared_task
from celery.exceptions import SoftTimeLimitExceeded
from cryptography.x509 import load_pem_x509_certificate, NameOID, ExtensionOID
from cryptography.x509 import ExtensionNotFound, SignatureAlgorithmOID, DNSName
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl.ec import _EllipticCurvePublicKey
from cryptography.hazmat.backends.openssl.dh import _DHPublicKey
from cryptography.hazmat.backends.openssl.rsa import _RSAPublicKey
from cryptography.hazmat.backends.openssl.dsa import _DSAPublicKey
from cryptography.hazmat.primitives import hashes
from django.conf import settings
from django.core.cache import cache
from django.db import transaction
from itertools import product
from nassl import _nassl
from nassl.ocsp_response import OcspResponseNotTrustedError

from . import SetupUnboundContext, shared
from .dispatcher import check_registry, post_callback_hook
from .http_headers import HeaderCheckerContentEncoding, http_headers_check
from .http_headers import HeaderCheckerStrictTransportSecurity
from .shared import MAX_REDIRECT_DEPTH, NoIpError, resolve_dane
from .shared import results_per_domain, aggregate_subreports
from .shared import DebugConnection, ModernConnection
from .shared import ConnectionHandshakeException
from .shared import ConnectionSocketException
from .shared import SSLV23, SSLV2, SSLV3, TLSV1, TLSV1_1, TLSV1_2, TLSV1_3
from .shared import HTTPSConnection
from .. import scoring, categories
from .. import batch, batch_shared_task, redis_id
from ..models import DaneStatus, DomainTestTls, MailTestTls, WebTestTls
from ..models import ForcedHttpsStatus, ZeroRttStatus, OcspStatus
from ..templatetags.translate import INJECTED_TRANSLATION_START
from ..templatetags.translate import INJECTED_TRANSLATION_END


logger = logging.getLogger(__name__)

# Workaround for https://github.com/eventlet/eventlet/issues/413 for eventlet
# while monkey patching. That way we can still catch subprocess.TimeoutExpired
# instead of just Exception which may intervene with Celery's own exceptions.
# Gevent does not have the same issue.
import eventlet
if eventlet.patcher.is_monkey_patched('subprocess'):
    subprocess = eventlet.import_patched('subprocess')
else:
    import subprocess

try:
    from ssl import OP_NO_SSLv2, OP_NO_SSLv3
except ImportError as e:
    # Support for older python versions, not for use in production
    if settings.DEBUG:
        OP_NO_SSLv2 = 16777216
        OP_NO_SSLv3 = 33554432
    else:
        raise e


# Load OpenSSL data about cipher suites
cipher_infos = dict()
with open(settings.TLS_CIPHERS) as f:
    # Create a dictionary of CipherInfo objects, keyed by OpenSSL cipher name
    # with each CipherInfo object having fields named after the columns in the
    # input CSV file. The expected CSV header row results in the following
    # CipherInfo fields:
    #   - major                - RFC cipher code (first part, e.g. 0x00)
    #     minor                - RFC cipher code (second part, e.g. 0x0D)
    #     name                 - OpenSSL cipher name (e.g. DH-DSS-DES-CBC3-SHA)
    #     tls_version          - SSL/TLS version that the cipher can be used with (e.g. SSLv3)
    #     kex_algs             - forward slash separated set of key exchange algorithm names (e.g. DH/DSS)
    #     auth_alg             - authentication algorithm name (e.g. DH)
    #     bulk_enc_alg         - bulk encryption algorithm name (e.g. 3DES)
    #     bulk_enc_alg_sec_len - bulk encryption algorithm secret key bit length (e.g. 168)
    #     mac_alg              - message authentication code algorithm name (e.g. SHA1)
    # Later rows with the same cipher name as an earlier row will replace the
    # earlier entry.
    cipher_infos = {
        r["name"]: namedtuple(
            "CipherInfo", r.keys())(*r.values()) for r in csv.DictReader(f)}
logger.debug(f'Read data on {len(cipher_infos)} ciphers from "{settings.TLS_CIPHERS}."')


# Based on:
# https://tools.ietf.org/html/rfc5246#page-45 (7.4.1.4.1 Signature Algorithms)
# https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_set1_sigalgs_list.html
# https://www.openssl.org/docs/man1.1.0/man3/SSL_CONF_cmd.html
# https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-16
# https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-18
# openssl list -1 -digest-commands
# NCSC 2.0 Table 2 - Algorithms for certificate verification
# NCSC 2.0 Table 4 - Algorithms for key exchange
# NCSC 2.0 Table 5 - Hash functions for key exchange
# Put SHA-512|384|256 first because NCSC 2.0 says anything else is phase out.
KEX_TLS12_HASHALG_PREFERRED_ORDER = [
    'SHA512',
    'SHA384',
    'SHA256',
    'SHA224',
    'SHA1',
    'MD5'
]
# Put the key exchange signature algorithms in reverse order compared to those
# preferred by NCSC 2.0 so that we can report the worst csae, connection wtih an
# insufficient algorithm, and if that fails we can detect connection wtih a phase
# out algorithm. The alternative is to connect separately with each separate
# algorithm which is a lot of TLS connections, and more connections can result in
# being blocked when performing mail TLS tests.
KEX_TLS12_SIGALG_PREFERRED_ORDER = [
    'RSA',
    'DSA',
    'ECDSA',
]
KEX_TLS12_SORTED_ALG_COMBINATIONS = map('+'.join, product(
    KEX_TLS12_SIGALG_PREFERRED_ORDER, KEX_TLS12_HASHALG_PREFERRED_ORDER))
KEX_TLS12_SIGALG_PREFERENCE = ':'.join(KEX_TLS12_SORTED_ALG_COMBINATIONS)

# Based on:
# https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-signaturescheme
# https://www.openssl.org/docs/man1.1.0/man3/SSL_CONF_cmd.html
# NCSC 2.0 Table 2 - Algorithms for certificate verification
# NCSC 2.0 Table 4 - Algorithms for key exchange
# NCSC 2.0 Table 5 - Hash functions for key exchange
KEX_TLS13_SIG_SCHEME_PREFERRED_ORDER = [
    'ecdsa_secp521r1_sha512',
    'ecdsa_secp384r1_sha384',
    'ecdsa_secp256r1_sha256',
    'rsa_pss_pss_sha512',
    'rsa_pss_pss_sha384',
    'rsa_pss_pss_sha256',
    'rsa_pss_rsae_sha512',
    'rsa_pss_rsae_sha384',
    'rsa_pss_rsae_sha256',
    'rsa_pkcs1_sha512',
    'rsa_pkcs1_sha384',
    'rsa_pkcs1_sha256',
    'ed25519',
    'ed448',
    'rsa_pkcs1_sha1',
    'ecdsa_sha1'
]
KEX_TLS13_SIGALG_PREFERENCE = ':'.join(KEX_TLS13_SIG_SCHEME_PREFERRED_ORDER)
KEX_SIGALG_PHASEOUT_REGEX = re.compile(r'RSA', re.IGNORECASE)

KEX_HASHFUNC_GOOD_REGEX_RAW = r'SHA(256|384|512)'
KEX_HASHFUNC_SUFFICIENT_REGEX_RAW = r'SHA224'
KEX_HASHFUNC_ACCEPTABLE_REGEX = re.compile(r'({}|{})'.format(
    KEX_HASHFUNC_GOOD_REGEX_RAW,
    KEX_HASHFUNC_SUFFICIENT_REGEX_RAW
), re.IGNORECASE)

BULK_ENC_CIPHERS_PHASEOUT = ['3DES']
BULK_ENC_CIPHERS_OTHER_PHASEOUT = ['SEED', 'ARIA']
BULK_ENC_CIPHERS_INSUFFICIENT = ['EXP', 'eNULL', 'RC4', 'DES', 'IDEA']
KEX_CIPHERS_PHASEOUT = ['RSA']
KEX_CIPHERS_INSUFFICIENT = ['DH', 'ECDH', 'eNULL', 'aNULL', 'PSK', 'SRP', 'MD5']
KEX_CIPHERS_INSUFFICIENT_AS_SET = frozenset(KEX_CIPHERS_INSUFFICIENT)

PHASE_OUT_CIPHERS = ':'.join(BULK_ENC_CIPHERS_PHASEOUT + BULK_ENC_CIPHERS_OTHER_PHASEOUT + KEX_CIPHERS_PHASEOUT)
INSUFFICIENT_CIPHERS = ':'.join(BULK_ENC_CIPHERS_INSUFFICIENT + KEX_CIPHERS_INSUFFICIENT)

# Some ciphers are not supported by LegacySslClient, only by SslClient which is
# based on more modern OpenSSL.
BULK_ENC_CIPHERS_INSUFFICIENT_MODERN = ['AESCCM8']
INSUFFICIENT_CIPHERS_MODERN = ':'.join(BULK_ENC_CIPHERS_INSUFFICIENT_MODERN)

# Based on: https://tools.ietf.org/html/rfc8446#page-133 (B.4 Cipher suites)
TLSV1_3_CIPHERS = frozenset([
    'TLS_AES_128_GCM_SHA256',
    'TLS_AES_256_GCM_SHA384',
    'TLS_CHACHA20_POLY1305_SHA256',
    'TLS_AES_128_CCM_SHA256',
    'TLS_AES_128_CCM_8_SHA256',
])

# Based on: https://tools.ietf.org/html/rfc7919#appendix-A
FFDHE2048_PRIME = int(
    (
        "FFFFFFFF FFFFFFFF ADF85458 A2BB4A9A AFDC5620 273D3CF1"
        "D8B9C583 CE2D3695 A9E13641 146433FB CC939DCE 249B3EF9"
        "7D2FE363 630C75D8 F681B202 AEC4617A D3DF1ED5 D5FD6561"
        "2433F51F 5F066ED0 85636555 3DED1AF3 B557135E 7F57C935"
        "984F0C70 E0E68B77 E2A689DA F3EFE872 1DF158A1 36ADE735"
        "30ACCA4F 483A797A BC0AB182 B324FB61 D108A94B B2C8E3FB"
        "B96ADAB7 60D7F468 1D4F42A3 DE394DF4 AE56EDE7 6372BB19"
        "0B07A7C8 EE0A6D70 9E02FCE1 CDF7E2EC C03404CD 28342F61"
        "9172FE9C E98583FF 8E4F1232 EEF28183 C3FE3B1B 4C6FAD73"
        "3BB5FCBC 2EC22005 C58EF183 7D1683B2 C6F34A26 C1B2EFFA"
        "886B4238 61285C97 FFFFFFFF FFFFFFFF"
    ).replace(' ', ''), 16)
FFDHE3072_PRIME = int(
    (
        "FFFFFFFF FFFFFFFF ADF85458 A2BB4A9A AFDC5620 273D3CF1"
        "D8B9C583 CE2D3695 A9E13641 146433FB CC939DCE 249B3EF9"
        "7D2FE363 630C75D8 F681B202 AEC4617A D3DF1ED5 D5FD6561"
        "2433F51F 5F066ED0 85636555 3DED1AF3 B557135E 7F57C935"
        "984F0C70 E0E68B77 E2A689DA F3EFE872 1DF158A1 36ADE735"
        "30ACCA4F 483A797A BC0AB182 B324FB61 D108A94B B2C8E3FB"
        "B96ADAB7 60D7F468 1D4F42A3 DE394DF4 AE56EDE7 6372BB19"
        "0B07A7C8 EE0A6D70 9E02FCE1 CDF7E2EC C03404CD 28342F61"
        "9172FE9C E98583FF 8E4F1232 EEF28183 C3FE3B1B 4C6FAD73"
        "3BB5FCBC 2EC22005 C58EF183 7D1683B2 C6F34A26 C1B2EFFA"
        "886B4238 611FCFDC DE355B3B 6519035B BC34F4DE F99C0238"
        "61B46FC9 D6E6C907 7AD91D26 91F7F7EE 598CB0FA C186D91C"
        "AEFE1309 85139270 B4130C93 BC437944 F4FD4452 E2D74DD3"
        "64F2E21E 71F54BFF 5CAE82AB 9C9DF69E E86D2BC5 22363A0D"
        "ABC52197 9B0DEADA 1DBF9A42 D5C4484E 0ABCD06B FA53DDEF"
        "3C1B20EE 3FD59D7C 25E41D2B 66C62E37 FFFFFFFF FFFFFFFF"
    ).replace(' ', ''), 16)
FFDHE4096_PRIME = int(
    (
        "FFFFFFFF FFFFFFFF ADF85458 A2BB4A9A AFDC5620 273D3CF1"
        "D8B9C583 CE2D3695 A9E13641 146433FB CC939DCE 249B3EF9"
        "7D2FE363 630C75D8 F681B202 AEC4617A D3DF1ED5 D5FD6561"
        "2433F51F 5F066ED0 85636555 3DED1AF3 B557135E 7F57C935"
        "984F0C70 E0E68B77 E2A689DA F3EFE872 1DF158A1 36ADE735"
        "30ACCA4F 483A797A BC0AB182 B324FB61 D108A94B B2C8E3FB"
        "B96ADAB7 60D7F468 1D4F42A3 DE394DF4 AE56EDE7 6372BB19"
        "0B07A7C8 EE0A6D70 9E02FCE1 CDF7E2EC C03404CD 28342F61"
        "9172FE9C E98583FF 8E4F1232 EEF28183 C3FE3B1B 4C6FAD73"
        "3BB5FCBC 2EC22005 C58EF183 7D1683B2 C6F34A26 C1B2EFFA"
        "886B4238 611FCFDC DE355B3B 6519035B BC34F4DE F99C0238"
        "61B46FC9 D6E6C907 7AD91D26 91F7F7EE 598CB0FA C186D91C"
        "AEFE1309 85139270 B4130C93 BC437944 F4FD4452 E2D74DD3"
        "64F2E21E 71F54BFF 5CAE82AB 9C9DF69E E86D2BC5 22363A0D"
        "ABC52197 9B0DEADA 1DBF9A42 D5C4484E 0ABCD06B FA53DDEF"
        "3C1B20EE 3FD59D7C 25E41D2B 669E1EF1 6E6F52C3 164DF4FB"
        "7930E9E4 E58857B6 AC7D5F42 D69F6D18 7763CF1D 55034004"
        "87F55BA5 7E31CC7A 7135C886 EFB4318A ED6A1E01 2D9E6832"
        "A907600A 918130C4 6DC778F9 71AD0038 092999A3 33CB8B7A"
        "1A1DB93D 7140003C 2A4ECEA9 F98D0ACC 0A8291CD CEC97DCF"
        "8EC9B55A 7F88A46B 4DB5A851 F44182E1 C68A007E 5E655F6A"
        "FFFFFFFF FFFFFFFF"
    ).replace(' ', ''), 16)
FFDHE6144_PRIME = int(
    (
        "FFFFFFFF FFFFFFFF ADF85458 A2BB4A9A AFDC5620 273D3CF1"
        "D8B9C583 CE2D3695 A9E13641 146433FB CC939DCE 249B3EF9"
        "7D2FE363 630C75D8 F681B202 AEC4617A D3DF1ED5 D5FD6561"
        "2433F51F 5F066ED0 85636555 3DED1AF3 B557135E 7F57C935"
        "984F0C70 E0E68B77 E2A689DA F3EFE872 1DF158A1 36ADE735"
        "30ACCA4F 483A797A BC0AB182 B324FB61 D108A94B B2C8E3FB"
        "B96ADAB7 60D7F468 1D4F42A3 DE394DF4 AE56EDE7 6372BB19"
        "0B07A7C8 EE0A6D70 9E02FCE1 CDF7E2EC C03404CD 28342F61"
        "9172FE9C E98583FF 8E4F1232 EEF28183 C3FE3B1B 4C6FAD73"
        "3BB5FCBC 2EC22005 C58EF183 7D1683B2 C6F34A26 C1B2EFFA"
        "886B4238 611FCFDC DE355B3B 6519035B BC34F4DE F99C0238"
        "61B46FC9 D6E6C907 7AD91D26 91F7F7EE 598CB0FA C186D91C"
        "AEFE1309 85139270 B4130C93 BC437944 F4FD4452 E2D74DD3"
        "64F2E21E 71F54BFF 5CAE82AB 9C9DF69E E86D2BC5 22363A0D"
        "ABC52197 9B0DEADA 1DBF9A42 D5C4484E 0ABCD06B FA53DDEF"
        "3C1B20EE 3FD59D7C 25E41D2B 669E1EF1 6E6F52C3 164DF4FB"
        "7930E9E4 E58857B6 AC7D5F42 D69F6D18 7763CF1D 55034004"
        "87F55BA5 7E31CC7A 7135C886 EFB4318A ED6A1E01 2D9E6832"
        "A907600A 918130C4 6DC778F9 71AD0038 092999A3 33CB8B7A"
        "1A1DB93D 7140003C 2A4ECEA9 F98D0ACC 0A8291CD CEC97DCF"
        "8EC9B55A 7F88A46B 4DB5A851 F44182E1 C68A007E 5E0DD902"
        "0BFD64B6 45036C7A 4E677D2C 38532A3A 23BA4442 CAF53EA6"
        "3BB45432 9B7624C8 917BDD64 B1C0FD4C B38E8C33 4C701C3A"
        "CDAD0657 FCCFEC71 9B1F5C3E 4E46041F 388147FB 4CFDB477"
        "A52471F7 A9A96910 B855322E DB6340D8 A00EF092 350511E3"
        "0ABEC1FF F9E3A26E 7FB29F8C 183023C3 587E38DA 0077D9B4"
        "763E4E4B 94B2BBC1 94C6651E 77CAF992 EEAAC023 2A281BF6"
        "B3A739C1 22611682 0AE8DB58 47A67CBE F9C9091B 462D538C"
        "D72B0374 6AE77F5E 62292C31 1562A846 505DC82D B854338A"
        "E49F5235 C95B9117 8CCF2DD5 CACEF403 EC9D1810 C6272B04"
        "5B3B71F9 DC6B80D6 3FDD4A8E 9ADB1E69 62A69526 D43161C1"
        "A41D570D 7938DAD4 A40E329C D0E40E65 FFFFFFFF FFFFFFFF"
    ).replace(' ', ''), 16)
FFDHE8192_PRIME = int(
    (
        "FFFFFFFF FFFFFFFF ADF85458 A2BB4A9A AFDC5620 273D3CF1"
        "D8B9C583 CE2D3695 A9E13641 146433FB CC939DCE 249B3EF9"
        "7D2FE363 630C75D8 F681B202 AEC4617A D3DF1ED5 D5FD6561"
        "2433F51F 5F066ED0 85636555 3DED1AF3 B557135E 7F57C935"
        "984F0C70 E0E68B77 E2A689DA F3EFE872 1DF158A1 36ADE735"
        "30ACCA4F 483A797A BC0AB182 B324FB61 D108A94B B2C8E3FB"
        "B96ADAB7 60D7F468 1D4F42A3 DE394DF4 AE56EDE7 6372BB19"
        "0B07A7C8 EE0A6D70 9E02FCE1 CDF7E2EC C03404CD 28342F61"
        "9172FE9C E98583FF 8E4F1232 EEF28183 C3FE3B1B 4C6FAD73"
        "3BB5FCBC 2EC22005 C58EF183 7D1683B2 C6F34A26 C1B2EFFA"
        "886B4238 611FCFDC DE355B3B 6519035B BC34F4DE F99C0238"
        "61B46FC9 D6E6C907 7AD91D26 91F7F7EE 598CB0FA C186D91C"
        "AEFE1309 85139270 B4130C93 BC437944 F4FD4452 E2D74DD3"
        "64F2E21E 71F54BFF 5CAE82AB 9C9DF69E E86D2BC5 22363A0D"
        "ABC52197 9B0DEADA 1DBF9A42 D5C4484E 0ABCD06B FA53DDEF"
        "3C1B20EE 3FD59D7C 25E41D2B 669E1EF1 6E6F52C3 164DF4FB"
        "7930E9E4 E58857B6 AC7D5F42 D69F6D18 7763CF1D 55034004"
        "87F55BA5 7E31CC7A 7135C886 EFB4318A ED6A1E01 2D9E6832"
        "A907600A 918130C4 6DC778F9 71AD0038 092999A3 33CB8B7A"
        "1A1DB93D 7140003C 2A4ECEA9 F98D0ACC 0A8291CD CEC97DCF"
        "8EC9B55A 7F88A46B 4DB5A851 F44182E1 C68A007E 5E0DD902"
        "0BFD64B6 45036C7A 4E677D2C 38532A3A 23BA4442 CAF53EA6"
        "3BB45432 9B7624C8 917BDD64 B1C0FD4C B38E8C33 4C701C3A"
        "CDAD0657 FCCFEC71 9B1F5C3E 4E46041F 388147FB 4CFDB477"
        "A52471F7 A9A96910 B855322E DB6340D8 A00EF092 350511E3"
        "0ABEC1FF F9E3A26E 7FB29F8C 183023C3 587E38DA 0077D9B4"
        "763E4E4B 94B2BBC1 94C6651E 77CAF992 EEAAC023 2A281BF6"
        "B3A739C1 22611682 0AE8DB58 47A67CBE F9C9091B 462D538C"
        "D72B0374 6AE77F5E 62292C31 1562A846 505DC82D B854338A"
        "E49F5235 C95B9117 8CCF2DD5 CACEF403 EC9D1810 C6272B04"
        "5B3B71F9 DC6B80D6 3FDD4A8E 9ADB1E69 62A69526 D43161C1"
        "A41D570D 7938DAD4 A40E329C CFF46AAA 36AD004C F600C838"
        "1E425A31 D951AE64 FDB23FCE C9509D43 687FEB69 EDD1CC5E"
        "0B8CC3BD F64B10EF 86B63142 A3AB8829 555B2F74 7C932665"
        "CB2C0F1C C01BD702 29388839 D2AF05E4 54504AC7 8B758282"
        "2846C0BA 35C35F5C 59160CC0 46FD8251 541FC68C 9C86B022"
        "BB709987 6A460E74 51A8A931 09703FEE 1C217E6C 3826E52C"
        "51AA691E 0E423CFC 99E9E316 50C1217B 624816CD AD9A95F9"
        "D5B80194 88D9C0A0 A1FE3075 A577E231 83F81D4A 3F2FA457"
        "1EFC8CE0 BA8A4FE8 B6855DFE 72B0A66E DED2FBAB FBE58A30"
        "FAFABE1C 5D71A87E 2F741EF8 C1FE86FE A6BBFDE5 30677F0D"
        "97D11D49 F7A8443D 0822E506 A9F4614E 011E2A94 838FF88C"
        "D68C8BB7 C5C6424C FFFFFFFF FFFFFFFF"
    ).replace(' ', ''), 16)
FFDHE_GENERATOR = 2
FFDHE_SUFFICIENT_PRIMES = [
    FFDHE8192_PRIME, FFDHE6144_PRIME, FFDHE4096_PRIME, FFDHE3072_PRIME]


# Maximum number of tries on failure to establish a connection.
# Useful on one-time errors on SMTP.
MAX_TRIES = 3

root_fingerprints = None
with open(settings.CA_FINGERPRINTS) as f:
    root_fingerprints = f.read().splitlines()

test_map = {
    'web': {
        'model': WebTestTls,
        'category': categories.WebTls(),
        'testset_name': 'webtestset',
        'port': 443,
    },
    'mail': {
        'model': MailTestTls,
        'category': categories.MailTls(),
        'testset_name': 'testset',
        'port': 25,
    },
}


class CertChecksMode(Enum):
    WEB = 0,
    MAIL = 1


@shared_task(bind=True)
def web_callback(self, results, domain, req_limit_id):
    """
    Save results in db.

    """
    webdomain, results = callback(results, domain, 'web')
    # Always calculate scores on saving.
    from ..probes import web_probe_tls
    web_probe_tls.rated_results_by_model(webdomain)
    post_callback_hook(req_limit_id, self.request.id)
    return results


@batch_shared_task(bind=True)
def batch_web_callback(self, results, domain):
    webdomain, results = callback(results, domain, 'web')
    # Always calculate scores on saving.
    from ..probes import batch_web_probe_tls
    batch_web_probe_tls.rated_results_by_model(webdomain)
    batch.scheduler.batch_callback_hook(webdomain, self.request.id)


@shared_task(bind=True)
def mail_callback(self, results, domain, req_limit_id):
    maildomain, results = callback(results, domain, 'mail')
    # Always calculate scores on saving.
    from ..probes import mail_probe_tls
    mail_probe_tls.rated_results_by_model(maildomain)
    post_callback_hook(req_limit_id, self.request.id)
    return results


@batch_shared_task(bind=True)
def batch_mail_callback(self, results, domain):
    maildomain, results = callback(results, domain, 'mail')
    # Always calculate scores on saving.
    from ..probes import batch_mail_probe_tls
    batch_mail_probe_tls.rated_results_by_model(maildomain)
    batch.scheduler.batch_callback_hook(maildomain, self.request.id)


@transaction.atomic
def callback(results, domain, test_type):
    results = results_per_domain(results)
    testdomain = test_map[test_type]['model'](domain=domain)
    testdomain.save()
    category = test_map[test_type]['category']
    if len(results.keys()) > 0:
        for addr, res in results.items():
            category = category.__class__()
            dttls = DomainTestTls(domain=addr)
            dttls.port = test_map[test_type]['port']
            save_results(
                dttls, res, addr, domain, test_map[test_type]['category'])
            build_report(dttls, category)
            dttls.save()
            getattr(testdomain, test_map[test_type]['testset_name']).add(dttls)
    build_summary_report(testdomain, category)
    testdomain.save()
    return testdomain, results


web_registered = check_registry("web_tls", web_callback, shared.resolve_a_aaaa)
batch_web_registered = check_registry(
    "batch_web_tls", batch_web_callback, shared.batch_resolve_a_aaaa)
mail_registered = check_registry(
    "mail_tls", mail_callback, shared.mail_get_servers)
batch_mail_registered = check_registry(
    "batch_mail_tls", batch_mail_callback, shared.batch_mail_get_servers)


@web_registered
@shared_task(
    bind=True,
    soft_time_limit=settings.SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext)
def web_cert(self, addrs, url, *args, **kwargs):
    return do_web_cert(addrs, url, self, *args, **kwargs)


@batch_web_registered
@batch_shared_task(
    bind=True,
    soft_time_limit=settings.BATCH_SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.BATCH_SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext)
def batch_web_cert(self, addrs, url, *args, **kwargs):
    return do_web_cert(addrs, url, self, *args, **kwargs)


@web_registered
@shared_task(
    bind=True,
    soft_time_limit=settings.SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext)
def web_conn(self, addrs, url, *args, **kwargs):
    return do_web_conn(addrs, url, *args, **kwargs)


@batch_web_registered
@batch_shared_task(
    bind=True,
    soft_time_limit=settings.BATCH_SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.BATCH_SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext)
def batch_web_conn(self, addrs, url, *args, **kwargs):
    return do_web_conn(addrs, url, *args, **kwargs)


@mail_registered
@shared_task(
    bind=True,
    soft_time_limit=settings.SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext)
def mail_smtp_starttls(self, mailservers, url, *args, **kwargs):
    return do_mail_smtp_starttls(mailservers, url, self, *args, **kwargs)


@batch_mail_registered
@batch_shared_task(
    bind=True,
    soft_time_limit=settings.BATCH_SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.BATCH_SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext)
def batch_mail_smtp_starttls(self, mailservers, url, *args, **kwargs):
    return do_mail_smtp_starttls(mailservers, url, self, *args, **kwargs)


@web_registered
@shared_task(
    bind=True,
    soft_time_limit=settings.SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext)
def web_http(self, addrs, url, *args, **kwargs):
    return do_web_http(addrs, url, self, *args, **kwargs)


@batch_web_registered
@batch_shared_task(
    bind=True,
    soft_time_limit=settings.BATCH_SHARED_TASK_SOFT_TIME_LIMIT_HIGH,
    time_limit=settings.BATCH_SHARED_TASK_TIME_LIMIT_HIGH,
    base=SetupUnboundContext)
def batch_web_http(self, addrs, url, *args, **kwargs):
    return do_web_http(addrs, url, self, args, **kwargs)


def save_results(model, results, addr, domain, category):
    """
    Save results in DB.

    """
    if isinstance(category, categories.WebTls):
        for testname, result in results:
            if testname == "tls_conn":
                model.server_reachable = result.get("server_reachable", True)
                model.tls_enabled = result.get("tls_enabled")
                model.tls_enabled_score = result.get("tls_enabled_score", 0)
                if model.server_reachable and model.tls_enabled:
                    model.dh_param = result.get("dh_param")
                    model.ecdh_param = result.get("ecdh_param")
                    model.fs_bad = result.get("fs_bad")
                    model.fs_phase_out = result.get("fs_phase_out")
                    model.fs_score = result.get("fs_score")
                    model.ciphers_bad = result.get("ciphers_bad")
                    model.ciphers_phase_out = result.get("ciphers_phase_out")
                    model.ciphers_score = result.get("ciphers_score")
                    model.cipher_order = result.get("cipher_order")
                    model.cipher_order_score = result.get("cipher_order_score")
                    model.protocols_bad = result.get("prots_bad")
                    model.protocols_phase_out = result.get("prots_phase_out")
                    model.protocols_score = result.get("prots_score")
                    model.compression = result.get("compression")
                    model.compression_score = result.get("compression_score")
                    model.secure_reneg = result.get("secure_reneg")
                    model.secure_reneg_score = result.get("secure_reneg_score")
                    model.client_reneg = result.get("client_reneg")
                    model.client_reneg_score = result.get("client_reneg_score")
                    model.zero_rtt = result.get("zero_rtt")
                    model.zero_rtt_score = result.get("zero_rtt_score")
                    model.ocsp_stapling = result.get("ocsp_stapling")
                    model.ocsp_stapling_score = result.get("ocsp_stapling_score")

            elif testname == "cert" and result.get("tls_cert"):
                model.cert_chain = result.get("chain")
                model.cert_trusted = result.get("trusted")
                model.cert_trusted_score = result.get("trusted_score")
                model.cert_pubkey_bad = result.get("pubkey_bad")
                model.cert_pubkey_phase_out = result.get("pubkey_phase_out")
                model.cert_pubkey_score = result.get("pubkey_score")
                model.cert_signature_bad = result.get("sigalg_bad")
                model.cert_signature_score = result.get("sigalg_score")
                model.cert_hostmatch_score = result.get("hostmatch_score")
                model.cert_hostmatch_bad = result.get("hostmatch_bad")
                model.dane_log = result.get("dane_log")
                model.dane_score = result.get("dane_score")
                model.dane_status = result.get("dane_status")
                model.dane_records = result.get("dane_records")
                model.dane_rollover = result.get("dane_rollover")

            elif testname == "http_checks":
                model.forced_https = result.get("forced_https")
                model.forced_https_score = result.get("forced_https_score")
                model.http_compression_enabled = result.get(
                    "http_compression_enabled")
                model.http_compression_score = result.get(
                    "http_compression_score")
                model.hsts_enabled = result.get("hsts_enabled")
                model.hsts_policies = result.get("hsts_policies")
                model.hsts_score = result.get("hsts_score")

    elif isinstance(category, categories.MailTls):
        for testname, result in results:
            if testname == "smtp_starttls":
                model.server_reachable = result.get("server_reachable", True)
                model.tls_enabled = result.get("tls_enabled")
                model.tls_enabled_score = result.get("tls_enabled_score", 0)
                model.could_not_test_smtp_starttls = result.get(
                    "could_not_test_smtp_starttls", False)
                if model.could_not_test_smtp_starttls:
                    # Special case where we couldn't connect for a test.
                    # Ignore all the subtests for this server.
                    continue

                if model.server_reachable and model.tls_enabled:
                    model.dh_param = result.get("dh_param")
                    model.ecdh_param = result.get("ecdh_param")
                    model.fs_bad = result.get("fs_bad")
                    model.fs_score = result.get("fs_score")
                    model.ciphers_bad = result.get("ciphers_bad")
                    model.ciphers_score = result.get("ciphers_score")
                    model.protocols_bad = result.get("prots_bad")
                    model.protocols_score = result.get("prots_score")
                    model.compression = result.get("compression")
                    model.compression_score = result.get("compression_score")
                    model.secure_reneg = result.get("secure_reneg")
                    model.secure_reneg_score = result.get("secure_reneg_score")
                    model.client_reneg = result.get("client_reneg")
                    model.client_reneg_score = result.get("client_reneg_score")
                if result.get("tls_cert"):
                    model.cert_chain = result.get("chain")
                    model.cert_trusted = result.get("trusted")
                    model.cert_trusted_score = result.get("trusted_score")
                    model.cert_pubkey_bad = result.get("pubkey_bad")
                    model.cert_pubkey_score = result.get("pubkey_score")
                    model.cert_signature_bad = result.get("sigalg_bad")
                    model.cert_signature_score = result.get("sigalg_score")
                    model.cert_hostmatch_score = result.get("hostmatch_score")
                    model.cert_hostmatch_bad = result.get("hostmatch_bad")
                    model.dane_log = result.get("dane_log")
                    model.dane_score = result.get("dane_score")
                    model.dane_status = result.get("dane_status")
                    model.dane_records = result.get("dane_records")
                    model.dane_rollover = result.get("dane_rollover")

    model.save()


def build_report(dttls, category):
    status_phase_out = (
        INJECTED_TRANSLATION_START
        + 'results security-level phase-out'
        + INJECTED_TRANSLATION_END)

    if isinstance(category, categories.WebTls):
        if not dttls.server_reachable:
            category.subtests['https_exists'].result_unreachable()
        elif not dttls.tls_enabled:
            category.subtests['https_exists'].result_bad()
        else:
            category.subtests['https_exists'].result_good()

            if dttls.forced_https == ForcedHttpsStatus.good:
                category.subtests['https_forced'].result_good()
            elif dttls.forced_https == ForcedHttpsStatus.no_http:
                category.subtests['https_forced'].result_no_http()
            elif dttls.forced_https == ForcedHttpsStatus.bad:
                category.subtests['https_forced'].result_bad()

            if dttls.hsts_enabled:
                if dttls.hsts_score == scoring.WEB_TLS_HSTS_GOOD:
                    category.subtests['https_hsts'].result_good(
                        dttls.hsts_policies)
                else:
                    category.subtests['https_hsts'].result_bad_max_age(
                        dttls.hsts_policies)
            else:
                category.subtests['https_hsts'].result_bad()

            if dttls.http_compression_enabled:
                category.subtests['http_compression'].result_bad()
            else:
                category.subtests['http_compression'].result_good()

            if not dttls.dh_param and not dttls.ecdh_param:
                category.subtests['fs_params'].result_no_dh_params()
            else:
                fs_all = []
                fs_all.extend(dttls.fs_bad)
                fs_all.extend([
                    '{prot} ({status})'.format(prot=fs, status=status_phase_out)
                    for fs in dttls.fs_phase_out])
                if len(dttls.fs_bad) > 0:
                    category.subtests['fs_params'].result_bad(fs_all)
                elif len(dttls.fs_phase_out) > 0:
                    category.subtests['fs_params'].result_phase_out(fs_all)
                else:
                    category.subtests['fs_params'].result_good()

            ciphers_all = []
            ciphers_all.extend(dttls.ciphers_bad)
            ciphers_all.extend([
                '{cipher} ({status})'.format(cipher=cipher, status=status_phase_out)
                for cipher in dttls.ciphers_phase_out])
            if len(dttls.ciphers_bad) > 0:
                category.subtests['tls_ciphers'].result_bad(ciphers_all)
            elif len(dttls.ciphers_phase_out) > 0:
                category.subtests['tls_ciphers'].result_phase_out(ciphers_all)
            else:
                category.subtests['tls_ciphers'].result_good()

            if dttls.cipher_order:
                category.subtests['tls_cipher_order'].result_good()
            else:
                category.subtests['tls_cipher_order'].result_bad()

            prots = []
            prots.extend(dttls.protocols_bad)
            prots.extend([
                '{prot} ({status})'.format(prot=prot, status=status_phase_out)
                for prot in dttls.protocols_phase_out])
            if len(dttls.protocols_bad) > 0:
                category.subtests['tls_version'].result_bad(prots)
            elif len(dttls.protocols_phase_out) > 0:
                category.subtests['tls_version'].result_phase_out(prots)
            else:
                category.subtests['tls_version'].result_good()

            if dttls.compression == 1:
                category.subtests['tls_compression'].result_bad()
            elif dttls.compression == 0:
                category.subtests['tls_compression'].result_good()
            else:
                category.subtests['tls_compression'].result_na()

            if dttls.secure_reneg == 1:
                category.subtests['renegotiation_secure'].result_good()
            elif dttls.secure_reneg == 0:
                category.subtests['renegotiation_secure'].result_bad()
            else:
                category.subtests['renegotiation_secure'].result_na()

            if dttls.client_reneg == 1:
                category.subtests['renegotiation_client'].result_bad()
            elif dttls.client_reneg == 0:
                category.subtests['renegotiation_client'].result_good()
            else:
                category.subtests['renegotiation_client'].result_na()

            if dttls.cert_trusted == 0:
                category.subtests['cert_trust'].result_good()
            else:
                category.subtests['cert_trust'].result_bad(dttls.cert_chain)

            if dttls.cert_pubkey_score is None:
                pass
            else:
                pubkey_all = []
                pubkey_all.extend(dttls.cert_pubkey_bad)
                pubkey_all.extend([
                    '{pubkey} ({status})'.format(pubkey=pubkey, status=status_phase_out)
                    for pubkey in dttls.cert_pubkey_phase_out])
                if len(dttls.cert_pubkey_bad) > 0:
                    category.subtests['cert_pubkey'].result_bad(pubkey_all)
                elif len(dttls.cert_pubkey_phase_out) > 0:
                    category.subtests['cert_pubkey'].result_phase_out(pubkey_all)
                else:
                    category.subtests['cert_pubkey'].result_good()

            if dttls.cert_signature_score is None:
                pass
            elif len(dttls.cert_signature_bad) > 0:
                category.subtests['cert_signature'].result_bad(
                    dttls.cert_signature_bad)
            else:
                category.subtests['cert_signature'].result_good()

            if dttls.cert_hostmatch_score is None:
                pass
            elif len(dttls.cert_hostmatch_bad) > 0:
                category.subtests['cert_hostmatch'].result_bad(
                    dttls.cert_hostmatch_bad)
            else:
                category.subtests['cert_hostmatch'].result_good()

            if dttls.dane_status == DaneStatus.none:
                category.subtests['dane_exists'].result_bad()
            elif dttls.dane_status == DaneStatus.none_bogus:
                category.subtests['dane_exists'].result_bogus()
            else:
                category.subtests['dane_exists'].result_good(
                    dttls.dane_records)

                if dttls.dane_status == DaneStatus.validated:
                    category.subtests['dane_valid'].result_good()
                elif dttls.dane_status == DaneStatus.failed:
                    category.subtests['dane_valid'].result_bad()

                # Disabled for now.
                # if dttls.dane_rollover:
                #     category.subtests['dane_rollover'].result_good()
                # else:
                #     category.subtests['dane_rollover'].result_bad()

            if dttls.zero_rtt == ZeroRttStatus.good:
                category.subtests['zero_rtt'].result_good()
            elif dttls.zero_rtt == ZeroRttStatus.na:
                category.subtests['zero_rtt'].result_na()
            elif dttls.zero_rtt == ZeroRttStatus.bad:
                category.subtests['zero_rtt'].result_bad()

            if dttls.ocsp_stapling == OcspStatus.good:
                category.subtests['ocsp_stapling'].result_good()
            elif dttls.ocsp_stapling == OcspStatus.not_trusted:
                category.subtests['ocsp_stapling'].result_not_trusted()
            elif dttls.ocsp_stapling == OcspStatus.ok:
                category.subtests['ocsp_stapling'].result_ok()

    elif isinstance(category, categories.MailTls):
        if dttls.could_not_test_smtp_starttls:
            category.subtests['starttls_exists'].result_could_not_test()
        elif not dttls.server_reachable:
            category.subtests['starttls_exists'].result_unreachable()
        elif not dttls.tls_enabled:
            category.subtests['starttls_exists'].result_bad()
        else:
            category.subtests['starttls_exists'].result_good()

            if not dttls.dh_param and not dttls.ecdh_param:
                category.subtests['fs_params'].result_no_dh_params()
            else:
                if len(dttls.fs_bad) > 0:
                    category.subtests['fs_params'].result_bad(dttls.fs_bad)
                else:
                    category.subtests['fs_params'].result_good()

            if len(dttls.ciphers_bad) > 0:
                category.subtests['tls_ciphers'].result_bad(dttls.ciphers_bad)
            else:
                category.subtests['tls_ciphers'].result_good()

            if len(dttls.protocols_bad) > 0:
                category.subtests['tls_version'].result_bad(
                    dttls.protocols_bad)
            else:
                category.subtests['tls_version'].result_good()

            if dttls.compression:
                category.subtests['tls_compression'].result_bad()
            else:
                category.subtests['tls_compression'].result_good()

            if dttls.secure_reneg:
                category.subtests['renegotiation_secure'].result_good()
            else:
                category.subtests['renegotiation_secure'].result_bad()

            if dttls.client_reneg:
                category.subtests['renegotiation_client'].result_bad()
            else:
                category.subtests['renegotiation_client'].result_good()

            if dttls.cert_trusted == 0:
                category.subtests['cert_trust'].result_good()
            else:
                category.subtests['cert_trust'].result_bad(dttls.cert_chain)

            if dttls.cert_pubkey_score is None:
                pass
            elif len(dttls.cert_pubkey_bad) > 0:
                category.subtests['cert_pubkey'].result_bad(
                    dttls.cert_pubkey_bad)
            else:
                category.subtests['cert_pubkey'].result_good()

            if dttls.cert_signature_score is None:
                pass
            elif len(dttls.cert_signature_bad) > 0:
                category.subtests['cert_signature'].result_bad(
                    dttls.cert_signature_bad)
            else:
                category.subtests['cert_signature'].result_good()

            if dttls.cert_hostmatch_score is None:
                pass
            elif len(dttls.cert_hostmatch_bad) > 0:
                # HACK: for DANE-TA(2) and hostname mismatch!
                # Give a fail only if DANE-TA *is* present, otherwise info.
                if has_daneTA(dttls.dane_records):
                    category.subtests['cert_hostmatch'].result_has_daneTA(
                        dttls.cert_hostmatch_bad)
                else:
                    category.subtests['cert_hostmatch'].result_bad(
                        dttls.cert_hostmatch_bad)
            else:
                category.subtests['cert_hostmatch'].result_good()

            if dttls.dane_status == DaneStatus.none:
                category.subtests['dane_exists'].result_bad()
            elif dttls.dane_status == DaneStatus.none_bogus:
                category.subtests['dane_exists'].result_bogus()
            else:
                category.subtests['dane_exists'].result_good(
                    dttls.dane_records)

                if dttls.dane_status == DaneStatus.validated:
                    category.subtests['dane_valid'].result_good()
                elif dttls.dane_status == DaneStatus.failed:
                    category.subtests['dane_valid'].result_bad()

                if dttls.dane_rollover:
                    category.subtests['dane_rollover'].result_good()
                else:
                    category.subtests['dane_rollover'].result_bad()

    dttls.report = category.gen_report()


def build_summary_report(testtls, category):
    """
    Build the summary report for all the IP addresses.

    """
    category = category.__class__()
    if isinstance(category, categories.WebTls):
        category.subtests['https_exists'].result_bad()
        server_set = testtls.webtestset

    elif isinstance(category, categories.MailTls):
        category.subtests['starttls_exists'].result_no_mailservers()
        server_set = testtls.testset

    report = category.gen_report()
    subreports = {}
    for server_test in server_set.all():
        subreports[server_test.domain] = server_test.report

    aggregate_subreports(subreports, report)
    testtls.report = report


def dane(
        url, port, chain, task, dane_cb_data, score_none, score_none_bogus,
        score_failed, score_validated):
    """
    Check if there are TLSA records, if they are valid and if a DANE rollover
    scheme is currently in place.

    """
    score = score_none
    status = DaneStatus.none
    records = []
    stdout = ""
    rollover = False

    continue_testing = True

    cb_data = dane_cb_data or resolve_dane(task, port, url)

    # Check if there is a TLSA record, if TLSA records are bogus or NXDOMAIN is
    # returned for the TLSA domain (faulty signer).
    if not cb_data.get('data'):
        if cb_data.get('bogus'):
            status = DaneStatus.none_bogus
            score = score_none_bogus
        continue_testing = False
    else:
        if cb_data.get('secure'):
            # If there is a secure TLSA record check for the existence of
            # possible bogus (unsigned) NXDOMAIN in A.
            tmp_data = resolve_dane(task, port, url, check_nxdomain=True)
            if tmp_data.get('nxdomain') and tmp_data.get('bogus'):
                status = DaneStatus.none_bogus
                score = score_none_bogus
                continue_testing = False
        elif cb_data.get('bogus'):
            status = DaneStatus.failed
            score = score_failed
            continue_testing = False

    if not continue_testing:
        return dict(
            dane_score=score,
            dane_status=status,
            dane_log=stdout,
            dane_records=records,
            dane_rollover=rollover,
        )

    # Record TLSA data and also check for DANE rollover types.
    # Accepted pairs are:
    # * 3 1 x - 3 1 x
    # * 3 1 x - 2 1 x
    two_one_x = 0
    three_one_x = 0
    for cert_usage, selector, match, data in cb_data["data"]:
        records.append("{} {} {} {}".format(cert_usage, selector, match, data))
        if selector == 1:
            if cert_usage == 2:
                two_one_x += 1
            elif cert_usage == 3:
                three_one_x += 1
    if three_one_x > 1 or (three_one_x and two_one_x):
        rollover = True

    # Remove the trailing dot if any.
    hostname = url.rstrip(".")

    chain_pem = []
    for cert in chain:
        chain_pem.append(cert.as_pem())
    chain_txt = "\n".join(chain_pem)
    res = None
    with subprocess.Popen(
            [
                settings.LDNS_DANE,
                '-c', '/dev/stdin',  # Read certificate chain from stdin
                '-n',  # Do not validate hostname
                '-T',  # Exit status 2 for PKIX without (secure) TLSA records
                '-f', settings.CA_CERTIFICATES,  # CA file
                'verify', hostname, str(port),
            ],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            stdin=subprocess.PIPE, universal_newlines=True) as proc:

        try:
            res = proc.communicate(input=chain_txt, timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            res = proc.communicate()

    # status 0: DANE validate
    # status 1: ERROR
    # status 2: PKIX ok, no TLSA
    if res:
        stdout, stderr = res

        if ("No usable TLSA records" in stdout
                or "No usable TLSA records" in stderr):
            score = score_failed
            status = DaneStatus.failed
        elif ("No TLSA records" not in stdout
                and "No TLSA records" not in stderr):
            if proc.returncode == 0:
                score = score_validated
                status = DaneStatus.validated
            elif proc.returncode == 1:
                score = score_failed
                status = DaneStatus.failed

        # Log stderr if stdout is empty.
        if not stdout:
            stdout = stderr

    return dict(
        dane_score=score,
        dane_status=status,
        dane_log=stdout,
        dane_records=records,
        dane_rollover=rollover,
    )


def is_root_cert(cert):
    """
    Check if the certificate is a root certificate.

    """
    digest = cert.fingerprint(hashes.SHA1())
    digest = hexlify(digest).decode('ascii')
    return digest.upper() in root_fingerprints


def get_common_name(cert):
    """
    Get the commonName of the certificate.

    """
    value = "-"
    try:
        common_name = (
            cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0])
        if common_name:
            value = common_name.value
    except (IndexError, ValueError):
        pass
    return value


class DebugCertChain(object):
    """
    Class performing X509 cert checks NCSC Guidelines B3-*

    """
    def __new__(cls, chain):
        """
        In case the chain is None (ValueError from nassl) don't create an
        instance. Instead return None and it will be handled during the
        certificate checks.

        """
        if chain is None:
            return None
        return super(DebugCertChain, cls).__new__(cls)

    def __init__(self, chain):
        self.unparsed_chain = chain
        self.chain = [
            load_pem_x509_certificate(
                cert.as_pem().encode("ascii"), backend=default_backend())
            for cert in chain
        ]
        self.score_hostmatch_good = scoring.WEB_TLS_HOSTMATCH_GOOD
        self.score_hostmatch_bad = scoring.WEB_TLS_HOSTMATCH_BAD
        self.score_pubkey_good = scoring.WEB_TLS_PUBKEY_GOOD
        self.score_pubkey_bad = scoring.WEB_TLS_PUBKEY_BAD
        self.score_signature_good = scoring.WEB_TLS_SIGNATURE_GOOD
        self.score_signature_bad = scoring.WEB_TLS_SIGNATURE_BAD
        self.score_dane_none = scoring.WEB_TLS_DANE_NONE
        self.score_dane_none_bogus = scoring.WEB_TLS_DANE_NONE_BOGUS
        self.score_dane_failed = scoring.WEB_TLS_DANE_FAILED
        self.score_dane_validated = scoring.WEB_TLS_DANE_VALIDATED

    def check_hostname(self, url):
        """
        Check the hostname on the leaf certificate (commonName and SANs).

        """
        bad_hostmatch = []
        common_name = get_common_name(self.chain[0])
        try:
            sans = self.chain[0].extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            sans = sans.value.get_values_for_type(DNSName)
        except ExtensionNotFound:
            sans = []

        ssl_cert_parts = {
            'subject': (tuple([('commonName', common_name)]),),
            'subjectAltName': tuple([('DNS', name) for name in sans]),
        }
        try:
            ssl.match_hostname(ssl_cert_parts, url.rstrip("."))
            hostmatch_score = self.score_hostmatch_good
        except ssl.CertificateError:
            hostmatch_score = self.score_hostmatch_bad
            bad_hostmatch.append(common_name)
            bad_hostmatch.append(sans)
        return hostmatch_score, bad_hostmatch

    # NCSC guidelines B3-3, B3-4, B3-5
    def check_pubkey(self):
        bad_pubkey = []
        phase_out_pubkey = []
        pubkey_score = self.score_pubkey_good
        for cert in self.chain:
            common_name = get_common_name(cert)
            public_key = cert.public_key()
            public_key_type = type(public_key)
            bits = public_key.key_size

            failed_key_type = ""
            curve = ""
            if public_key_type is _RSAPublicKey and bits < 2048:
                failed_key_type = "RSAPublicKey"
            elif public_key_type is _DSAPublicKey and bits < 2048:
                failed_key_type = "DSAPublicKey"
            elif public_key_type is _DHPublicKey and bits < 2048:
                failed_key_type = "DHPublicKey"
            elif public_key_type is _EllipticCurvePublicKey:
                curve = public_key.curve.name
                if (curve not in [
                        "brainpoolP512r1",
                        "brainpoolP384r1",
                        "brainpoolP256r1",
                        "secp521r1",
                        "secp384r1",
                        "secp256r1",
                        "prime256v1",
                        ] or bits < 224):
                    failed_key_type = "EllipticCurvePublicKey"
            if failed_key_type:
                message = "{}: {}-{} bits".format(
                    common_name, failed_key_type, bits)
                if curve:
                    message += ", curve: {}".format(curve)
                if curve == "secp224r1":
                    phase_out_pubkey.append(message)
                else:
                    bad_pubkey.append(message)
                    pubkey_score = self.score_pubkey_bad
        return pubkey_score, bad_pubkey, phase_out_pubkey

    def check_sigalg(self):
        """
        Check whether the certificate is signed using a good algorithm.

        Good algorithms are: sha512, sha384, sha256
        NCSC guideline B3-2

        """
        bad_sigalg = {}
        sigalg_score = self.score_signature_good
        for cert in self.chain:
            # Only validate signarture of non-root certificates
            if not is_root_cert(cert):
                sigalg = cert.signature_algorithm_oid
                # Check oids
                if sigalg not in (
                        SignatureAlgorithmOID.RSA_WITH_SHA256,
                        SignatureAlgorithmOID.RSA_WITH_SHA384,
                        SignatureAlgorithmOID.RSA_WITH_SHA512,
                        SignatureAlgorithmOID.ECDSA_WITH_SHA256,
                        SignatureAlgorithmOID.ECDSA_WITH_SHA384,
                        SignatureAlgorithmOID.ECDSA_WITH_SHA512,
                        SignatureAlgorithmOID.DSA_WITH_SHA256):
                    bad_sigalg[get_common_name(cert)] = sigalg._name
                    sigalg_score = self.score_signature_bad
        return sigalg_score, bad_sigalg

    def chain_str(self):
        """
        Return a list containing the commonNames of the certificate chain.

        """
        chain_str = []
        for cert in self.chain:
            chain_str.append(get_common_name(cert))

        return chain_str

    def check_dane(self, url, port, task, dane_cb_data=None):
        return dane(
            url, port, self.unparsed_chain, task, dane_cb_data,
            self.score_dane_none, self.score_dane_none_bogus,
            self.score_dane_failed, self.score_dane_validated)


class DebugCertChainMail(DebugCertChain):
    """
    Subclass of DebugCertChain to define the scores used for the mailtest.

    """
    def __init__(self, chain):
        super(DebugCertChainMail, self).__init__(chain)
        self.score_hostmatch_good = scoring.MAIL_TLS_HOSTMATCH_GOOD
        self.score_hostmatch_bad = scoring.MAIL_TLS_HOSTMATCH_BAD
        self.score_pubkey_good = scoring.MAIL_TLS_PUBKEY_GOOD
        self.score_pubkey_bad = scoring.MAIL_TLS_PUBKEY_BAD
        self.score_signature_good = scoring.MAIL_TLS_SIGNATURE_GOOD
        self.score_signature_bad = scoring.MAIL_TLS_SIGNATURE_BAD
        self.score_dane_none = scoring.MAIL_TLS_DANE_NONE
        self.score_dane_none_bogus = scoring.MAIL_TLS_DANE_NONE_BOGUS
        self.score_dane_failed = scoring.MAIL_TLS_DANE_FAILED
        self.score_dane_validated = scoring.MAIL_TLS_DANE_VALIDATED


class DebugSMTPConnectionCouldNotTestException(Exception):
    """
    Used on the SMTP STARTTLS test.

    Used when we have time outs on establishing a connection or when a mail
    server replies with an error upon connecting.

    """
    pass


class DebugSMTPConnection(DebugConnection):
    def __init__(
            self, url, addr=None, version=SSLV23, shutdown=True,
            ciphers='ALL:COMPLEMENTOFALL', options=None, send_SNI=True):
        super(DebugSMTPConnection, self).__init__(
            url, addr, version, shutdown, ciphers, options, send_SNI)
        self.score_compression_good = scoring.MAIL_TLS_COMPRESSION_GOOD
        self.score_compression_bad = scoring.MAIL_TLS_COMPRESSION_BAD
        self.score_secure_reneg_good = scoring.MAIL_TLS_SECURE_RENEG_GOOD
        self.score_secure_reneg_bad = scoring.MAIL_TLS_SECURE_RENEG_BAD
        self.score_client_reneg_good = scoring.MAIL_TLS_CLIENT_RENEG_GOOD
        self.score_client_reneg_bad = scoring.MAIL_TLS_CLIENT_RENEG_BAD
        self.score_trusted_good = scoring.MAIL_TLS_TRUSTED_GOOD
        self.score_trusted_bad = scoring.MAIL_TLS_TRUSTED_BAD

    @staticmethod
    def readline(fd, maximum_bytes=4096):
        line = fd.readline(maximum_bytes)
        # print(line)
        return line.decode("ascii")

    def sock_setup(self):
        """
        Setup socket for SMTP STARTTLS.

        Retries to connect when we get an error code upon connecting.

        Raises DebugSMTPConnectionCouldNotTestException when we get no reply
        from the server or when the server still replies with an error code
        upon connecting after a number of retries.

        """
        self.port = 25
        self.sock_timeout = 24

        # If we get an error code(4xx, 5xx) in the first reply upon
        # connecting, we will retry in case it was a one time error.
        tries_left = MAX_TRIES
        self.sock = None
        retry = True
        while retry and tries_left > 0:
            retry = False
            try:
                self.sock = socket.create_connection(
                    (self.url, self.port), timeout=self.sock_timeout)
                fd = self.sock.makefile("rb")
                line = self.readline(fd)

                if (line and line[3] == " " and
                        (line[0] == '4' or line[0] == '5')):
                    # The server replied with an error code.
                    # We will retry to connect in case it was an one time
                    # error.
                    self.safe_shutdown(tls=False)
                    tries_left -= 1
                    retry = True
                    if tries_left <= 0:
                        raise DebugSMTPConnectionCouldNotTestException()
                    time.sleep(1)
                    continue

                while line and line[3] != " ":
                    line = self.readline(fd)

                self.sock.sendall(b"EHLO internet.nl\r\n")

                starttls = False
                line = self.readline(fd)

                while line and line[3] != " ":
                    if "STARTTLS" in line:
                        starttls = True
                    line = self.readline(fd)

                if starttls or "STARTTLS" in line:
                    self.sock.sendall(b"STARTTLS\r\n")
                    self.readline(fd)
                    fd.close()
                else:
                    fd.close()
                    raise ConnectionHandshakeException()

            except (socket.error, socket.timeout, socket.gaierror):
                # We didn't get a reply back, this means our packets
                # are dropped. This happened in cases where a rate
                # limiting mechanism was in place. Skip the test.
                if self.sock:
                    self.safe_shutdown(tls=False)
                raise DebugSMTPConnectionCouldNotTestException()
            except IOError as e:
                # We can't reach the server.
                if self.sock:
                    self.safe_shutdown(tls=False)
                if e.errno in [errno.ENETUNREACH, errno.EHOSTUNREACH,
                               errno.ECONNREFUSED, errno.ENOEXEC]:
                    raise DebugSMTPConnectionCouldNotTestException()
                raise e


class StarttlsDetails:
    """
    Class used to store starttls details for the mail test.

    """
    def __init__(
            self, debug_chain=None, trusted_score=None, conn_port=None,
            dane_cb_data=None):
        self.debug_chain = debug_chain
        self.trusted_score = trusted_score
        self.conn_port = conn_port
        self.dane_cb_data = dane_cb_data


def do_web_cert(addrs, url, task, *args, **kwargs):
    """
    Check the web server's certificate.

    """
    try:
        results = {}
        for addr in addrs:
            results[addr[1]] = cert_checks(
                url, CertChecksMode.WEB, task, addr, *args, **kwargs)
    except SoftTimeLimitExceeded:
        for addr in addrs:
            if not results.get(addr[1]):
                results[addr[1]] = dict(tls_cert=False)

    return ('cert', results)


def cert_checks(
        url, mode, task, addr=None, starttls_details=None,
        *args, **kwargs):
    """
    Perform certificate checks.

    """
    try:
        if mode == CertChecksMode.WEB:
            # First try to connect to HTTPS. We don't care for
            # certificates in port 443 if there is no HTTPS there.
            http_client, *unused = shared.http_fetch(
                url, af=addr[0], path="", port=443, addr=addr[1],
                depth=MAX_REDIRECT_DEPTH, task=web_cert, keep_conn_open=True)
            debug_cert_chain = DebugCertChain
            conn_handler = type(http_client.conn)
            http_client.close()
        elif mode == CertChecksMode.MAIL:
            conn_handler = DebugSMTPConnection
            debug_cert_chain = DebugCertChainMail
        else:
            raise ValueError

        if (not starttls_details or starttls_details.debug_chain is None
                or starttls_details.trusted_score is None
                or starttls_details.conn_port is None):
            # All the checks inside the smtp_starttls test are done in series.
            # If we have all the certificate related information we need from a
            # previous check, skip this connection.
            conn = conn_handler(
                url, addr=addr, version=SSLV23, shutdown=False,
                ciphers="!aNULL:ALL:COMPLEMENTOFALL")
            # check chain validity (sort of NCSC guideline B3-6)
            checker = get_connection_checker(conn)
            verify_score, verify_result = checker.check_cert_trust()
            debug_chain = debug_cert_chain(conn.get_peer_certificate_chain())
            conn_port = conn.port
            conn.safe_shutdown()
        else:
            verify_score, verify_result = starttls_details.trusted_score
            debug_chain = starttls_details.debug_chain
            conn_port = starttls_details.conn_port
    except (socket.error, http.client.BadStatusLine, NoIpError,
            ConnectionHandshakeException, ConnectionSocketException):
        return dict(tls_cert=False)

    if debug_chain is None:
        return dict(tls_cert=False)

    else:
        hostmatch_score, hostmatch_bad = debug_chain.check_hostname(url)
        pubkey_score, pubkey_bad, pubkey_phase_out = debug_chain.check_pubkey()
        sigalg_score, sigalg_bad = debug_chain.check_sigalg()
        chain_str = debug_chain.chain_str()

        if starttls_details:
            dane_results = debug_chain.check_dane(
                url, conn_port, task,
                dane_cb_data=starttls_details.dane_cb_data)
        else:
            dane_results = debug_chain.check_dane(
                url, conn_port, task)

        results = dict(
            tls_cert=True,
            chain=chain_str,
            trusted=verify_result,
            trusted_score=verify_score,
            pubkey_bad=pubkey_bad,
            pubkey_phase_out=pubkey_phase_out,
            pubkey_score=pubkey_score,
            sigalg_bad=sigalg_bad,
            sigalg_score=sigalg_score,
            hostmatch_bad=hostmatch_bad,
            hostmatch_score=hostmatch_score,
        )
        results.update(dane_results)

        return results


def do_web_conn(addrs, url, *args, **kwargs):
    """
    Start all the TLS related checks for the web test.

    """
    try:
        results = {}
        for addr in addrs:
            results[addr[1]] = check_web_tls(
                url, addr, args, kwargs)
    except SoftTimeLimitExceeded:
        for addr in addrs:
            if not results.get(addr[1]):
                results[addr[1]] = dict(tls_enabled=False)

    return ('tls_conn', results)


def do_mail_smtp_starttls(mailservers, url, task, *args, **kwargs):
    """
    Start all the TLS related checks for the mail test.

    If we already have cached results for these mailservers from another mail
    test use those to avoid contacting well known mailservers all the time.

    """
    results = {server: False for server, _ in mailservers}
    try:
        start = timer()
        # Sleep in order for the ipv6 mail test to finish.
        # Cheap counteraction for some mailservers that allow only one
        # concurrent connection per IP.
        time.sleep(5)
        cache_ttl = redis_id.mail_starttls.ttl
        while timer() - start < cache_ttl and not all(results.values()) > 0:
            for server, dane_cb_data in mailservers:
                if results[server]:
                    continue
                # Check if we already have cached results.
                cache_id = redis_id.mail_starttls.id.format(server)
                if cache.add(cache_id, False, cache_ttl):
                    # We do not have cached results, get them and cache them.
                    results[server] = check_mail_tls(
                        server, dane_cb_data, task)
                    cache.set(cache_id, results[server], cache_ttl)
                else:
                    results[server] = cache.get(cache_id, False)
            time.sleep(1)
        for server in results:
            if results[server] is False:
                results[server] = dict(
                    tls_enabled=False, could_not_test_smtp_starttls=True)

    except SoftTimeLimitExceeded:
        for server in results:
            if results[server] is False:
                results[server] = dict(
                    tls_enabled=False, could_not_test_smtp_starttls=True)
    return ('smtp_starttls', results)


def check_mail_tls(server, dane_cb_data, task):
    """
    Perform all the TLS related checks for this mail server in series.

    """
    try:
        starttls_details = StarttlsDetails()
        starttls_details.dane_cb_data = dane_cb_data
        send_SNI = (
            dane_cb_data.get('data')
            and dane_cb_data.get('secure'))

        try:
            # First try to connect with secure ciphers.
            conn = DebugSMTPConnection(
                server, shutdown=False, send_SNI=send_SNI,
                ciphers='ALL:COMPLEMENTOFALL:'
                        '!EXP:!aNULL:!PSK:!SRP:!IDEA:!DES:!eNULL:!RC4:'
                        '!MD5')
            checker = get_connection_checker(conn)

            secure_reneg_score, secure_reneg = checker.check_secure_reneg()
            client_reneg_score, client_reneg = checker.check_client_reneg()
            compression_score, compression = checker.check_compression()

            starttls_details.trusted_score = checker.check_cert_trust()
            starttls_details.debug_chain = DebugCertChainMail(
                conn.get_peer_certificate_chain())
            starttls_details.conn_port = conn.port

            conn.safe_shutdown()
            connected_with_secure_ciphers = True
        except ConnectionSocketException:
            return dict(server_reachable=False)
        except ConnectionHandshakeException:
            # If we cannot connect on the TLS layer try again including
            # weak ciphers.
            connected_with_secure_ciphers = False

        ciphers_score = scoring.MAIL_TLS_SUITES_OK
        ciphers_bad = []
        ncsc_bad_ciphers = 'EXP:aNULL:PSK:SRP:IDEA:DES:eNULL:RC4:MD5'
        try:
            conn = DebugSMTPConnection(
                server, ciphers=ncsc_bad_ciphers, shutdown=False,
                send_SNI=send_SNI)
        except ConnectionSocketException:
            return dict(server_reachable=False)
        except ConnectionHandshakeException:
            # If we still cannot connect on the TLS layer, too bad.
            if not connected_with_secure_ciphers:
                return dict(tls_enabled=False)
        else:
            ciphers_score = scoring.MAIL_TLS_SUITES_BAD
            curr_cipher = conn.get_current_cipher_name()
            ciphers_bad.append(curr_cipher)

            if not connected_with_secure_ciphers:
                checker = get_connection_checker(conn)
                secure_reneg_score, secure_reneg = checker.check_secure_reneg()
                client_reneg_score, client_reneg = checker.check_client_reneg()
                compression_score, compression = checker.check_compression()

                starttls_details.trusted_score = checker.trusted_score()
                starttls_details.debug_chain = DebugCertChainMail(
                    conn.get_peer_certificate_chain())
                starttls_details.conn_port = conn.port

            conn.safe_shutdown()

        # Number of connections: 2

        # SSLv2 and SSLv3 should not be supported
        prots_bad = []
        prots_score = scoring.MAIL_TLS_PROTOCOLS_GOOD
        try:
            DebugSMTPConnection(
                server, version=SSLV2, shutdown=True, send_SNI=send_SNI)
            prots_bad.append('SSLv2')
            prots_score = scoring.MAIL_TLS_PROTOCOLS_BAD
        except (ConnectionHandshakeException,
                ConnectionSocketException):
            pass
        try:
            DebugSMTPConnection(
                server, version=SSLV3, shutdown=True, send_SNI=send_SNI)
            prots_bad.append('SSLv3')
            prots_score = scoring.MAIL_TLS_PROTOCOLS_BAD
        except (ConnectionHandshakeException,
                ConnectionSocketException):
            pass

        # Number of connections: 4

        # Connect using DH(E) and ECDH(E) to get FS params
        dh_param, ecdh_param = False, False
        try:
            conn = DebugSMTPConnection(
                server, ciphers="DH:DHE:!aNULL",
                shutdown=False, send_SNI=send_SNI)
            dh_param = conn._openssl_str_to_dic(conn._ssl.get_dh_param())
            dh_param = dh_param["DH_Parameters"].strip("( bit)")
            conn.safe_shutdown()
        except (ConnectionHandshakeException,
                ConnectionSocketException):
            pass
        try:
            conn = DebugSMTPConnection(
                server, ciphers="ECDH:ECDHE:!aNULL",
                shutdown=False, send_SNI=send_SNI)
            ecdh_param = conn._openssl_str_to_dic(conn._ssl.get_ecdh_param())
            ecdh_param = ecdh_param["ECDSA_Parameters"].strip("( bit)")
            conn.safe_shutdown()
        except (ConnectionHandshakeException,
                ConnectionSocketException):
            pass

        fs_bad = []
        if dh_param and int(dh_param) < 2048:
            fs_bad.append("DH-{}".format(dh_param))
        if ecdh_param and int(ecdh_param) < 224:
            fs_bad.append("ECDH-{}".format(ecdh_param))

        if len(fs_bad) == 0:
            fs_score = scoring.MAIL_TLS_FS_OK
        else:
            fs_score = scoring.MAIL_TLS_FS_BAD

        # Number of connections: 6

        # Check the certificates.
        cert_results = cert_checks(
            server, CertChecksMode.MAIL, task,
            starttls_details=starttls_details)

        # Number of connections: {6, 7}

        # HACK for DANE-TA(2) and hostname mismatch!
        # Give a good hosmatch score if DANE-TA *is not* present.
        if (not has_daneTA(cert_results['dane_records'])
                and cert_results['hostmatch_bad']):
            cert_results['hostmatch_score'] = scoring.MAIL_TLS_HOSTMATCH_GOOD

        results = dict(
            tls_enabled=True,
            prots_bad=prots_bad,
            prots_score=prots_score,

            ciphers_bad=ciphers_bad,
            ciphers_score=ciphers_score,

            compression=compression,
            compression_score=compression_score,
            secure_reneg=secure_reneg,
            secure_reneg_score=secure_reneg_score,
            client_reneg=client_reneg,
            client_reneg_score=client_reneg_score,

            dh_param=dh_param,
            ecdh_param=ecdh_param,
            fs_bad=fs_bad,
            fs_score=fs_score,
        )
        results.update(cert_results)
    except DebugSMTPConnectionCouldNotTestException:
        # If we could not test something, fail the starttls test.
        # We do not show partial results.
        return dict(
            tls_enabled=False,
            could_not_test_smtp_starttls=True,
        )

    return results


def has_daneTA(tlsa_records):
    """
    Check if any of the TLSA records is of type DANE-TA(2).

    """
    for tlsa in tlsa_records:
        if tlsa.startswith("2"):
            return True
    return False


def get_connection_checker(conn):
    if isinstance(conn, DebugConnection) or isinstance(conn, ModernConnection):
        return ConnectionChecker(conn)
    elif isinstance(conn, DebugSMTPConnection):
        return conn
    else:
        raise ValueError()


class ConnectionChecker:
    def __init__(self, conn):
        self._conn = conn
        self._debug_conn = None
        self._seen_versions = set()
        self._seen_ciphers = dict()
        self._score_compression_good = scoring.WEB_TLS_COMPRESSION_GOOD
        self._score_compression_bad = scoring.WEB_TLS_COMPRESSION_BAD
        self._score_secure_reneg_good = scoring.WEB_TLS_SECURE_RENEG_GOOD
        self._score_secure_reneg_bad = scoring.WEB_TLS_SECURE_RENEG_BAD
        self._score_client_reneg_good = scoring.WEB_TLS_CLIENT_RENEG_GOOD
        self._score_client_reneg_bad = scoring.WEB_TLS_CLIENT_RENEG_BAD
        self._score_trusted_good = scoring.WEB_TLS_TRUSTED_GOOD
        self._score_trusted_bad = scoring.WEB_TLS_TRUSTED_BAD
        self._score_ocsp_staping_good = scoring.WEB_TLS_OCSP_STAPLING_GOOD
        self._score_ocsp_staping_ok = scoring.WEB_TLS_OCSP_STAPLING_OK
        self._score_ocsp_staping_bad = scoring.WEB_TLS_OCSP_STAPLING_BAD

        self._note_conn_details(conn)

    def __enter__(self):
        return self

    def __exit__(self, exception_type, exception_value, traceback):
        self.close()

    @property
    def debug_conn(self):
        # Lazily create a DebugConnection on first access, if needed. The client
        # of this class should use 'with' or .close() when finished with this
        # checker instance in order to clean up any specially created debug
        # connection.
        if self._debug_conn is None:
            if self._is_conn_good_for_legacy_checks():
                self._debug_conn = self._conn
            else:
                self._debug_conn = DebugConnection.from_conn(self._conn)
        return self._debug_conn

    @debug_conn.setter
    def debug_conn(self, value):
        self._debug_conn = value
        self._note_conn_details(self._debug_conn)

    def close(self):
        if self._debug_conn and self._debug_conn is not self._conn:
            self._debug_conn.safe_shutdown()
            self._debug_conn = None

    def _is_conn_good_for_legacy_checks(self):
        return (self._conn.get_ssl_version() == TLSV1_3
            or isinstance(self._conn, DebugConnection))

    def _note_conn_details(self, conn):
        ssl_version = conn.get_ssl_version()
        cipher_name = conn.get_current_cipher_name()
        conn_type = type(conn)

        # create missing dict keys if needed
        # don't use a set of ciphers because we care about the order in which
        # the ciphers were encountered
        self._seen_ciphers.setdefault(ssl_version, dict())
        self._seen_ciphers[ssl_version].setdefault(conn_type, list())

        # note the seen SSL version and cipher name
        self._seen_versions.add(ssl_version)
        ciphers = self._seen_ciphers[ssl_version][conn_type]
        if cipher_name not in ciphers:
            ciphers.append(cipher_name)

    def _debug_info(self, info):
        if (hasattr(settings, 'ENABLE_VERBOSE_TECHNICAL_DETAILS')
                and settings.ENABLE_VERBOSE_TECHNICAL_DETAILS):
            return ' [reason: {}] '.format(info)
        else:
            return ''

    def check_cert_trust(self):
        """
        Verify the certificate chain,

        """
        verify_result, _ = self._conn.get_certificate_chain_verify_result()
        if verify_result != 0:
            return self._score_trusted_bad, verify_result
        else:
            return self._score_trusted_good, verify_result

    def check_ocsp_stapling(self):
        # This will only work if SNI is in use and the handshake has already
        # been done.
        ocsp_response = self._conn.get_tlsext_status_ocsp_resp()
        if ocsp_response is not None and ocsp_response.status == 0:
            try:
                ocsp_response.verify(settings.CA_CERTIFICATES)
                return self._score_ocsp_staping_good, OcspStatus.good
            except OcspResponseNotTrustedError:
                return self._score_ocsp_staping_bad, OcspStatus.not_trusted
        else:
            return self._score_ocsp_staping_ok, OcspStatus.ok

    def check_secure_reneg(self):
        """
        Check if secure renegotiation is supported.

        Secure renegotiation should be supported, except in TLS 1.3.

        """
        if self._conn.get_ssl_version() == TLSV1_3:
            return self._score_secure_reneg_good, 1
        else:
            try:
                secure_reneg = self.debug_conn.get_secure_renegotiation_support()
                if secure_reneg:
                    secure_reneg_score = self._score_secure_reneg_good
                else:
                    secure_reneg_score = self._score_secure_reneg_bad
                return secure_reneg_score, secure_reneg
            except (ConnectionSocketException,
                    ConnectionHandshakeException):
            return self._score_secure_reneg_good, True

        # TLS 1.3 forbids renegotiaton.

    def check_client_reneg(self):
        """
        Check if client renegotiation is possible.

        Client renegotiation should not be possible.

        """
        if self._conn.get_ssl_version() == TLSV1_3:
            return self._score_client_reneg_good, False
        else:
            try:
                # this check requires a new connection, otherwise we encounter:
                # error:140940F5:SSL routines:ssl3_read_bytes:unexpected record
                with DebugConnection.from_conn(self._conn, version=SSLV23) as new_conn:
                    self._note_conn_details(new_conn)
                    # Step 1.
                    # Send reneg on open connection
                    new_conn.do_renegotiate()
                    # Step 2.
                    # Connection should now be closed, send 2nd reneg to verify
                    new_conn.do_renegotiate()
                    # If we are still here, client reneg is supported
                    client_reneg_score = self._score_client_reneg_bad
                    client_reneg = True
            except (socket.error, _nassl.OpenSSLError, IOError):
                client_reneg_score = self._score_client_reneg_good
                client_reneg = False
            return client_reneg_score, client_reneg

    def check_compression(self):
        """
        Check if TLS compression is enabled.

        TLS compression should not be enabled.

        """
        if self._conn.get_ssl_version() == TLSV1_3:
            return self._score_compression_good, False
        else:
            try:
                compression = self.debug_conn.get_current_compression_method() is not None
                if compression:
                    compression_score = self._score_compression_bad
                else:
                    compression_score = self._score_compression_good
                return compression_score, compression
            except (ConnectionSocketException,
                    ConnectionHandshakeException):
                return self._score_compression_good, 0

    def check_zero_rtt(self, explicit_conn=None):
        test_conn = self._conn if not explicit_conn else explicit_conn

        # This check isn't relevant to anything less than TLS 1.3.
        if not explicit_conn and test_conn.get_ssl_version() < TLSV1_3:
            return scoring.WEB_TLS_ZERO_RTT_NA, ZeroRttStatus.na

        # we require an existing connection, as 0-RTT is only possible with
        # connections after the first so that the SSL session can be re-used.
        # is_handshake_completed() will be false if we didn't complete the
        # connection handshake yet or we subsequently shutdown the connection.
        if not test_conn.is_handshake_completed():
            raise ValueError()

        session = test_conn.get_session()

        # does the server announce support for early data?
        # assumes that at least some data was already exchanged because, with
        # NGINX at least, get_max_early_data() will be <= 0 if no prior data
        # has been written to and read from the connection even if early data
        # is actually supported.
        if session.get_max_early_data() <= 0:
            return scoring.WEB_TLS_ZERO_RTT_GOOD, ZeroRttStatus.good

        # terminate the current connection and re-connect using the previous
        # SSL session details then try and write early data to the connection
        test_conn.safe_shutdown()

        try:
            test_conn.connect(do_handshake_on_connect=False)
            test_conn.set_session(session)
            if test_conn._ssl.get_early_data_status() == 0:
                http_client = HTTPSConnection.fromconn(test_conn)
                http_client.putrequest('GET', '/')
                http_client.endheaders()
                if (test_conn._ssl.get_early_data_status() == 1 and
                    not test_conn.is_handshake_completed()):
                    test_conn.do_handshake()
                    self._note_conn_details(test_conn)
                    if test_conn._ssl.get_early_data_status() == 2:
                        # 0-RTT status is bad unless the target responds with
                        # HTTP status code 425 Too Early. See:
                        # https://tools.ietf.org/id/draft-ietf-httpbis-replay-01.html#rfc.section.5.2
                        if http_client.getresponse().status == 425:
                            return ZeroRttStatus.good, scoring.WEB_TLS_ZERO_RTT_GOOD
        except (ConnectionHandshakeException,
                ConnectionSocketException,
                IOError):
            pass

        # todo: ensure the handshake is completed ready for the next check that
        # uses this connection?

        return scoring.WEB_TLS_ZERO_RTT_BAD, ZeroRttStatus.bad

    def check_protocol_versions(self):
        # Test for TLS 1.1 and TLS 1.0 as these are "phase out" per NCSC 2.0
        # Test for SSL v2 and v3 as these are "insecure" per NCSC 2.0
        prots_bad = []
        prots_phase_out = []
        prots_score = scoring.WEB_TLS_PROTOCOLS_GOOD

        prot_test_configs = [
            ( TLSV1_1, 'TLS 1.1', prots_phase_out, scoring.WEB_TLS_PROTOCOLS_GOOD ),
            ( TLSV1,   'TLS 1.0', prots_phase_out, scoring.WEB_TLS_PROTOCOLS_GOOD ),
            ( SSLV3,   'SSL 3.0', prots_bad,       scoring.WEB_TLS_PROTOCOLS_BAD ),
            ( SSLV2,   'SSL 2.0', prots_bad,       scoring.WEB_TLS_PROTOCOLS_BAD ),
        ]

        for version, name, prot_set, score in prot_test_configs:
            if version in self._seen_versions:
                # No need to test for this protocol version as we already
                # connected with it.
                connected = True
            else:
                # We already tested TLS 1.3 at the beginning when calling
                # http_fetch(), so we only need to use DebugConnection as it
                # can handle the older protocol versions.
                try:
                    with DebugConnection.from_conn(self._conn, version=version):
                        connected = True
                        self._note_conn_details(self._conn)
                except (ConnectionSocketException,
                        ConnectionHandshakeException):
                    connected = False

            if connected:
                prot_set.append(name)
                prots_score = score

        result_dict = {
            'bad': prots_bad,
            'phase_out': prots_phase_out,
        }

        return prots_score, result_dict

    def _check_dh_params(self):
        dh_param, ecdh_param = False, False
        dh_ff_p, dh_ff_g = False, False

        try:
            # We have to use DebugConnection because ModernConnection doesn't
            # have the _openssl_str_to_dic() method, but use of custom DH FF
            # groups is not relevant for TLS 1.3/ModernConnection anyway.
            with DebugConnection.from_conn(self._conn, ciphers="DH:DHE:!aNULL") as new_conn:
                self._note_conn_details(new_conn)
                dh_param = new_conn._openssl_str_to_dic(new_conn._ssl.get_dh_param())
                dh_ff_p = int(dh_param["prime"], 16) # '0x...'
                dh_ff_g = int(dh_param["generator"].partition(' ')[0]) # 'n (0xn)'
                dh_param = dh_param["DH_Parameters"].strip("( bit)")  # '(n bit)'
        except (ConnectionSocketException,
                ConnectionHandshakeException):
            pass

        try:
            with DebugConnection.from_conn(self._conn, ciphers="ECDH:ECDHE:!aNULL") as new_conn:
                self._note_conn_details(new_conn)
                ecdh_param = new_conn._openssl_str_to_dic(new_conn._ssl.get_ecdh_param())
                ecdh_param = ecdh_param["ECDSA_Parameters"].strip("( bit)")
        except (ConnectionSocketException,
                ConnectionHandshakeException):
            pass

        fs_bad = []
        fs_phase_out = []

        if dh_param and int(dh_param) < 2048:
            fs_bad.append("DH-{}{}".format(dh_param, self._debug_info("short bit len")))
        elif dh_ff_p and dh_ff_g:
            if (dh_ff_g == FFDHE_GENERATOR and
                dh_ff_p in FFDHE_SUFFICIENT_PRIMES):
                pass
            elif (dh_ff_g == FFDHE_GENERATOR and
                  dh_ff_p == FFDHE2048_PRIME):
                fs_phase_out.append("DH-FFDHE2048{}".format(self._debug_info("weak ff group")))
            else:
                fs_bad.append("DH-{}{}".format(dh_param, self._debug_info("unknown ff group")))

        if ecdh_param and int(ecdh_param) < 224:
            fs_bad.append("ECDH-{}{}".format(ecdh_param, self._debug_info("short bit len")))

        return fs_bad, fs_phase_out, dh_param, ecdh_param

    def _check_key_exchange_signature_algorithm_and_hash_func(self):
        bad = []
        phase_out = []

        # Re-connect with explicit signature algorithm preferences and
        # determine signature related properties of the connection. Only
        # TLS >= 1.2 support specifying the preferred signature algorithms as
        # ClientHello extensions (of which SignatureAlgorithm is one) were only
        # introduced in TLS 1.2. Further, according to the OpenSSL 1.1.1 docs
        # (see: https://www.openssl.org/docs/man1.1.1/man3/SSL_get_peer_signature_type_nid.html)
        # calls to get_peer_signature_xxx() are only supported for TLS >= 1.2.
        if self._conn.get_ssl_version() >= TLSV1_2:
            if self._conn.get_ssl_version() == TLSV1_3:
                sig_algs = KEX_TLS13_SIGALG_PREFERENCE
            elif self._conn.get_ssl_version() == TLSV1_2:
                sig_algs = KEX_TLS12_SIGALG_PREFERENCE

            kex_hash_func, kex_sig_type = None, None
            try:
                # Only OpenSSL 1.1.1 has the necessary functions for
                # determining the key exchange signature algorithm and hash
                # function in use, so use ModernConnection (which is based on
                # OpenSSL 1.1.1). Additionally, only ModernConnection supports
                # passing the signature algorithm preference to the server.
                with ModernConnection.from_conn(self._conn,
                        signature_algorithms=sig_algs,
                        version=self._conn.get_ssl_version()) as new_conn:
                    # Ensure that the requirement in the OpenSSL docs that the
                    # peer has signed a message is satisfied by exchanging data
                    # with the server.
                    http_client = HTTPSConnection.fromconn(new_conn)
                    http_client.putrequest('GET', '/')
                    http_client.endheaders()
                    http_client.getresponse()
                    kex_hash_func = new_conn.get_peer_signature_digest()
                    kex_sig_type = new_conn.get_peer_signature_type()
            except (ConnectionSocketException,
                    ConnectionHandshakeException):
                pass

            if kex_hash_func and not KEX_HASHFUNC_ACCEPTABLE_REGEX.search(kex_hash_func):
                phase_out.append("{}{}".format(kex_hash_func, self._debug_info("weak hash function")))

            if kex_sig_type and KEX_SIGALG_PHASEOUT_REGEX.search(kex_sig_type):
                phase_out.append("{}{}".format(kex_sig_type, self._debug_info("weak signature algorithm")))

        return bad, phase_out

    def check_forward_secrecy(self):
        fs_bad, fs_phase_out, dh_param, ecdh_param = self._check_dh_params()
        kex_bad, kex_phase_out = self._check_key_exchange_signature_algorithm_and_hash_func()

        fs_bad.extend(kex_bad)
        fs_phase_out.extend(kex_phase_out)

        if len(fs_bad) == 0:
            fs_score = scoring.WEB_TLS_FS_OK
        else:
            fs_score = scoring.WEB_TLS_FS_BAD

        result_dict = {
            'bad': fs_bad,
            'phase_out': fs_phase_out,
            'dh_param': dh_param,
            'ecdh_param': ecdh_param
        }

        return fs_score, result_dict

    def check_cipher_order(self):
        """
        Check whether the server respects its own cipher order or if that
        order can be overriden by the client.

        """

        def _get_seen_ciphers_for_conn(conn):
            ssl_version = conn.get_ssl_version()
            conn_type = type(conn)
            return self._seen_ciphers[ssl_version][conn_type]

        def _get_nth_or_default(collection, index, default):
            return collection[index] if index < len(collection) else default

        cipher_order_score = scoring.WEB_TLS_CIPHER_ORDER_GOOD
        cipher_order = True

        # For this test we need two ciphers, one selected by the server and
        # another selected by the server when the former was disallowed by the
        # client. We then reverse the order of these two ciphers in the list of
        # ciphers that the client tells the server it supports, and see if the
        # server still selects the same cipher. We hope that the server doesn't
        # consider both ciphers to be of equal weight and thus happy to use
        # either irrespective of order. 

        # Which ciphers seen so far during checks are relevant for self._conn?
        relevant_ciphers = _get_seen_ciphers_for_conn(self._conn)

        # Get the cipher name of at least one cipher that works with self._conn
        first_cipher = relevant_ciphers[0]
        second_cipher = _get_nth_or_default(relevant_ciphers, 1, None)

        try:
            # If we haven't yet connected with a second cipher, do so now.
            if not second_cipher:
                if self._conn.get_ssl_version() < TLSV1_3:
                    cipher_string = f'!{first_cipher}:ALL:COMPLEMENTOFALL'
                    with self._conn.dup(ciphers=cipher_string) as new_conn:
                        second_cipher = new_conn.get_current_cipher_name()
                else:
                    # OpenSSL 1.1.1 TLS 1.3 cipher preference strings do not
                    # support '!' thus we must instead manually exclude the
                    # current cipher using the known small set of allowed TLS
                    # 1.3 ciphers. See '-ciphersuites' at:
                    #   https://www.openssl.org/docs/man1.1.1/man1/ciphers.html
                    remaining_ciphers = set(TLSV1_3_CIPHERS)
                    remaining_ciphers.remove(first_cipher)
                    cipher_string = ':'.join(remaining_ciphers)
                    with self._conn.dup(tls13ciphers=cipher_string) as new_conn:
                        second_cipher = new_conn.get_current_cipher_name()

            if first_cipher != second_cipher:
                # Now that we know of two ciphers that can be used to connect
                # to the server, one of which was chosen in preference to the
                # other, ask the server to use them in reverse order and
                # confirm that the server instead continues to impose its own
                # order preference on the cipher selection process:
                cipher_string = f'{second_cipher}:{first_cipher}'
                if self._conn.get_ssl_version() < TLSV1_3:
                    with self._conn.dup(ciphers=cipher_string) as new_conn:
                        newly_selected_cipher = new_conn.get_current_cipher_name()
                else:
                    with self._conn.dup(tls13ciphers=cipher_string) as new_conn:
                        newly_selected_cipher = new_conn.get_current_cipher_name()

                if newly_selected_cipher == second_cipher:
                    cipher_order_score = scoring.WEB_TLS_CIPHER_ORDER_BAD
                    cipher_order = False
        except ConnectionHandshakeException:
            # Unable to connect with a second cipher or with reversed cipher
            # order.
            pass

        return cipher_order_score, cipher_order

    def check_ciphers(self):
        ciphers_bad = set()
        ciphers_phase_out = set()
        ciphers_score = scoring.WEB_TLS_SUITES_OK

        if self._conn.get_ssl_version() < TLSV1_3:
            # 1. Cipher name string based matching is fragile, e.g. OpenSSL
            #    cipher names do not always indicate all algorithms in use nor
            #    is it clear to me that the presence of RSA for example means
            #    RSA for authentication and/or RSA for key exchange.
            # 2. It's also not clear to me if letting OpenSSL do the matching
            #    is sufficient because, again using RSA as an example, the
            #    OpenSSL documentation says that "RSA" as a cipher string
            #    matches "Cipher suites using RSA key exchange or
            #    authentication", but NCSC 2.0 only classifies the cipher as
            #    "phase out" IFF the cipher uses RSA for key exchange (it's
            #    okay for the cipher to use RSA for authentication aka
            #    certificate verification).
            # 3. There appears to be an issue with DH/ECDH matching by OpenSSL
            #    because it matches ECDHE/DHE ciphers too.
            # 4. Even if OpenSSL matches yields the correct results, by
            #    doing explicit cipher property checks we make the test logic
            #    less magic, more transparent and less dependent on OpenSSL.
            # 5. This all raises the question can we even trust that when asked
            #    to select a particular cipher (suite) can the server be
            #    trusted to honour the request? Do we have to validate that
            #    when asked to match a cipher of a particular type that such a
            #    cipher is actually negotiated (assuming that both client and
            #    server support such a cipher)?
            #
            # An example from the OpenSSL ciphers command output:
            #    0xC0,0x30 - ECDHE-RSA-AES256-GCM-SHA384 TLSv1.2 Kx=ECDH \
            #                Au=RSA  Enc=AESGCM(256) Mac=AEAD
            #
            # This cipher uses RSA for authentication but NOT for key exchange.
            # You cannot tell that from the OpenSSL cipher name alone, nor per
            # the OpenSSL documentation can you rely on OpenSSL to exclude the
            # cipher when you request RSA ciphers (e.g. to test for ciphers to
            # mark as "phase out"). UPDATE: It might be possible to exclude
            # ciphers that use RSA for authentication by including !aRSA in the
            # cipher string.
            #
            # For ciphers that we don't have any information about, fallback to
            # trusting OpenSSL cipher matching.
            #
            # HOWEVER:
            #
            # - This is more complicated than just telling OpenSSL the cipher
            #   groups we want.
            # - Parsing the openssl ciphers -V output is a pain because use of
            #   slash separators doesn't appear to be consistent.
            # - The OpenSSL docs about RSA as a cipher do not appear to be
            #   correct, or at least in the context of connection establishment
            #   rather than certificate signing it seems that RSA does what we
            #   want, i.e. filters only ciphers using RSA for key exchange, not
            #   ciphers using RSA for authentication.
            # - The key exchange algorithm data from openssl ciphers -V doesn't
            #   appear to be accurate/granular enough for our use because for
            #   example NCSC 2.0 says only ECDHE key exchange is "Good" and
            #   that the following cipher is "Good": (output from ciphers -V)
            #     TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 - \
            #       ECDHE-ECDSA-AES256-GCM-SHA384 TLSv1.2 Kx=ECDH \
            #       Au=ECDSA Enc=AESGCM(256) Mac=AEAD
            #   Note that it says that Kx=ECDH, _NOT_ ECDHE. Either the ciphers
            #   command output is incorrect, or ECDHE is not distinguishable in
            #   this way from ECDH and so we cannot use the ciphers -V output
            #   to check cipher properties...
            #   However, also odd is that ciphers that _DO_ have ECDHE or DHE
            #   key exchange algorithms always seem to be pre-shared key (PSK)
            #   as well.

            # Connect using bad or phase out ciphers. To detect if a cipher
            # we can connect with is a phase out cipher we need to match it by
            # name to a cipher from out the phase out set. However, not all
            # cipher names include the name contained in the set, e.g. an RSA
            # based cipher may not include the word RSA in the cipher name. To
            # match these ciphers we test phase out ciphers first, any cipher
            # we can connect with must be a phase out cipher, then we try after
            # that to connect with the "insufficient" ciphers. If somehow a
            # cipher is present in both sets we treat it as "insufficient" as
            # this is more negative for the customer than the "phase out"
            # classification. For example OpenSSL cipher 'AES256-SHA' is an RSA
            # based cipher with IANA name 'TLS_RSA_WITH_AES_256_CBC_SHA'. More
            # https://testssl.sh/openssl-iana.mapping.html for more examples.
            cipher_test_configs = [
                ( 'phase out',    DebugConnection,  PHASE_OUT_CIPHERS,           ciphers_phase_out ),
                ( 'insufficient', DebugConnection,  INSUFFICIENT_CIPHERS,        ciphers_bad       ),
                ( 'insufficient', ModernConnection, INSUFFICIENT_CIPHERS_MODERN, ciphers_bad       ),
            ]
            for description, this_conn_handler, all_ciphers_to_test, cipher_set in cipher_test_configs:
                for cipher_suite in all_ciphers_to_test.split(':'):
                    ciphers_to_test = cipher_suite
                    while True:
                        try:
                            with this_conn_handler.from_conn(
                                self._conn, ciphers=ciphers_to_test,
                                version=SSLV23
                            ) as new_conn:
                                self._note_conn_details(new_conn)
                                curr_cipher = new_conn.get_current_cipher_name()
                                # curr_cipher is likely not exactly the same as any
                                # of the active cipher suites in the cipher string,
                                # e.g. if the cipher string contains 'RSA' then
                                # curr_cipher could be the name of an actual cipher
                                # that uses RSA.

                                # Update the cipher string to exclude the current
                                # cipher (not cipher suite) from the cipher suite
                                # negotiation on the next connection.
                                ciphers_to_test = "!{}:{}".format(
                                    curr_cipher, ciphers_to_test)

                                # Try and classify the cipher based on what we know
                                # about it.
                                ci = cipher_infos.get(curr_cipher)
                                if ci:
                                    ci_kex_algs = frozenset(ci.kex_algs.split('/'))
                                    # TODO: sometimes ci_kex_algs is not slash
                                    # separated but still contains more than one
                                    # algorithm, e.g. DHEPSK, ECDHEPSK, RSAPSK
                                    # Make the gen script insert a forward
                                    # slash in these cases?
                                    # TODO: sometimes bulk_enc_alg is also
                                    # slash separated, e.g. CHACH20/POLY1305.
                                    # TODO: ci_kex_algs can also be 'any'.
                                    if (
                                        not ci_kex_algs.isdisjoint(KEX_CIPHERS_INSUFFICIENT_AS_SET)
                                        and (
                                            (ci_kex_algs == 'DH' and 'DHE' not in curr_cipher) or
                                            (ci_kex_algs == 'ECDH' and 'ECDHE' not in curr_cipher)
                                        )
                                    ):
                                        ciphers_bad.add('{}{}'.format(curr_cipher, self._debug_info(f'kex alg "{ci.kex_algs}"')))
                                    elif (ci.bulk_enc_alg in BULK_ENC_CIPHERS_INSUFFICIENT or
                                        ci.bulk_enc_alg in BULK_ENC_CIPHERS_INSUFFICIENT_MODERN):
                                        ciphers_bad.add('{}{}'.format(curr_cipher, self._debug_info(f'bulk enc alg "{ci.bulk_enc_alg}"')))
                                    elif not ci_kex_algs.isdisjoint(KEX_CIPHERS_PHASEOUT):
                                        ciphers_phase_out.add('{}{}'.format(curr_cipher, self._debug_info(f'kex alg matches "{ci.kex_algs}"')))
                                    elif ci.bulk_enc_alg in BULK_ENC_CIPHERS_PHASEOUT:
                                        ciphers_phase_out.add('{}{}'.format(curr_cipher, self._debug_info(f'bulk enc alg matches "{ci.bulk_enc_alg}"')))
                                    else:
                                        # This cipher is actually okay. Perhaps
                                        # OpenSSL matched it based on the cipher
                                        # string we gave it, but actually we didn't
                                        # mean for it to be matched (i.e. there is
                                        # a problem with our cipher string). This
                                        # happens for ECDHE-RSA-AES256-GCM-SHA384
                                        # when the cipher string given to OpenSSL
                                        # contains ECDH. ECDH according to NCSC 2.0
                                        # is "insufficient" because it cannot
                                        # provide forward secrecy, while ECDHE can
                                        # and so is "good". Currently we catch this
                                        # particular case above by checking the 
                                        # cipher name for DHE/ECDHE. I'd prefer a
                                        # way to test for the kex algorithm being
                                        # ephemeral but I don't know how to do that
                                        # at the moment, if it's even possible.
                                        # TODO: Warn somewhere that this happened?
                                        logger.debug(f'Disregarding OpenSSL cipher match of cipher "{curr_cipher}" to suite "{cipher_suite}" for test group "{description}" and URL "{self._conn.url}". Reason: cipher is ephemeral by name.')
                                        pass
                                else:
                                    # TODO: I know of at least two ciphers that are
                                    # missing: (both 3DES)
                                    #   - ADH-DES-CBC3-SHA
                                    #   - AECDH-DES-CBC3-SHA
                                    # We don't know anything about these ciphers.
                                    # Fall back to trusting that OpenSSL has only
                                    # agreed a cipher with the remote that matches
                                    # our cipher specification, and that our cipher
                                    # specification doesn't accidentally match
                                    # something we didn't expect or intend to match
                                    # (e.g. a cipher that authenticates with RSA
                                    # but doesn't use RSA for key exchange).
                                    # However, watch out for cases like cipher suite
                                    # 'DH' matching 'DHE-RSA-CHACHA20-POLY1305-OLD'
                                    # which looks like it is ephemeral (DH_E_) and
                                    # thus actually okay. This is the same as the
                                    # case above, but above we know the cipher in our
                                    # cipher_info "database", here we don't know the
                                    # cipher and have to use the cipher suite as a
                                    # hint as to why the cipher was matched.
                                    if ((cipher_suite == 'ECDH' and not 'ECDHE' in curr_cipher) or
                                        (cipher_suite == 'DH' and not 'DHE' in curr_cipher)):
                                        logger.debug(f'Honoring OpenSSL cipher match of cipher "{curr_cipher}" to suite "{cipher_suite}" for test group "{description}" and URL "{self._conn.url}". Reason: cipher is not in our database."')
                                        cipher_set.add('{}{}'.format(curr_cipher, self._debug_info(f'unknown cipher matches "{cipher_suite}"')))
                        except (ConnectionSocketException,
                                ConnectionHandshakeException):
                            break

            # If in both sets, only keep the cipher in the bad set.
            ciphers_phase_out -= ciphers_bad

            if len(ciphers_bad) > 0:
                ciphers_score = scoring.WEB_TLS_SUITES_BAD
            elif len(ciphers_phase_out) > 0:
                ciphers_score = scoring.WEB_TLS_SUITES_OK

        result_dict = {
            'bad': list(ciphers_bad),
            'phase_out': list(ciphers_phase_out)
        }

        return ciphers_score, result_dict


def check_web_tls(url, addr=None, *args, **kwargs):
    """
    Check the webserver's TLS configuration.

    """

    def connect_to_web_server():
        http_client, *unused = shared.http_fetch(
            url, af=addr[0], path="", port=443, addr=addr[1],
            depth=MAX_REDIRECT_DEPTH, task=web_conn,
            keep_conn_open=True)
        return http_client.conn

    try:
        # connect with the higest possible TLS version assuming that the server
        # responds to HTTP requests, then check some interesting properties of
        # this 'best possible' connection.
        with connect_to_web_server() as conn:
            # save some details about the connection for later
            conn_handler = type(conn)
            conn_ssl_version = conn.get_ssl_version()
            conn_cipher = conn.get_current_cipher_name()

            with get_connection_checker(conn) as checker:
                # note: additional connections will be created by the checker
                # as needed
                ocsp_stapling_score, ocsp_stapling = checker.check_ocsp_stapling()
                secure_reneg_score, secure_reneg = checker.check_secure_reneg()
                client_reneg_score, client_reneg = checker.check_client_reneg()
                compression_score, compression = checker.check_compression()
                fs_score, fs_result = checker.check_forward_secrecy()
                ciphers_score, ciphers_result = checker.check_ciphers()
                zero_rtt_score, zero_rtt = checker.check_zero_rtt()
                prots_score, prots_result = checker.check_protocol_versions()
                cipher_order_score, cipher_order = checker.check_cipher_order()

                return dict(
                    tls_enabled=True,
                    prots_bad=prots_result['bad'],
                    prots_phase_out=prots_result['phase_out'],
                    prots_score=prots_score,

                    ciphers_bad=ciphers_result['bad'],
                    ciphers_phase_out=ciphers_result['phase_out'],
                    ciphers_score=ciphers_score,
                    cipher_order_score=cipher_order_score,
                    cipher_order = cipher_order,

                    secure_reneg=secure_reneg,
                    secure_reneg_score=secure_reneg_score,
                    client_reneg=client_reneg,
                    client_reneg_score=client_reneg_score,
                    compression=compression,
                    compression_score=compression_score,

                    dh_param=fs_result['dh_param'],
                    ecdh_param=fs_result['ecdh_param'],
                    fs_bad=fs_result['bad'],
                    fs_phase_out=fs_result['phase_out'],
                    fs_score=fs_score,

                    zero_rtt_score=zero_rtt_score,
                    zero_rtt=zero_rtt,

                    ocsp_stapling=ocsp_stapling,
                    ocsp_stapling_score=ocsp_stapling_score,
                )
    except (socket.error, http.client.BadStatusLine, NoIpError,
            ConnectionHandshakeException,
            ConnectionSocketException):
        return dict(tls_enabled=False)


def do_web_http(addrs, url, task, *args, **kwargs):
    """
    Start all the HTTP related checks for the web test.

    """
    try:
        results = {}
        for addr in addrs:
            results[addr[1]] = http_checks(addr, url, task)

    except SoftTimeLimitExceeded:
        for addr in addrs:
            if not results.get(addr[1]):
                results[addr[1]] = dict(
                    forced_https=False,
                    forced_https_score=scoring.WEB_TLS_FORCED_HTTPS_BAD,
                    http_compression_enabled=True,
                    http_compression_score=(
                        scoring.WEB_TLS_HTTP_COMPRESSION_BAD),
                    hsts_enabled=False,
                    hsts_policies=[],
                    hsts_score=scoring.WEB_TLS_HSTS_BAD,
                )

    return ('http_checks', results)


def http_checks(addr, url, task):
    """
    Perform the HTTP header and HTTPS redirection checks for this webserver.

    """
    forced_https_score, forced_https = forced_http_check(addr, url, task)
    header_checkers = [
        HeaderCheckerContentEncoding(),
        HeaderCheckerStrictTransportSecurity(),
    ]
    header_results = http_headers_check(addr, url, header_checkers, task)

    results = {
        'forced_https': forced_https,
        'forced_https_score': forced_https_score,
    }
    results.update(header_results)
    return results


def forced_http_check(addr, url, task):
    """
    Check if the webserver is properly configured with HTTPS redirection.

    """
    # First connect on port 80 and see if we get refused
    try:
        conn, res, headers, visited_hosts = shared.http_fetch(
            url, af=addr[0], path="", port=80, task=task, addr=addr[1])

    except (socket.error, http.client.BadStatusLine, NoIpError):
        # If we got refused on port 80 the first time
        # return the FORCED_HTTPS_NO_HTTP status and score
        return scoring.WEB_TLS_FORCED_HTTPS_NO_HTTP, ForcedHttpsStatus.no_http

    # Valid if same domain, or *higher* domain. Use case:
    # www.example.com:80 -> example.com:443. Example.com:443 can set HSTS
    # with includeSubdomains
    forced_https = ForcedHttpsStatus.bad
    forced_https_score = scoring.WEB_TLS_FORCED_HTTPS_BAD

    if 443 in visited_hosts and conn.port == 443:
        for visited_host in visited_hosts[443]:
            if visited_host in url:
                forced_https = ForcedHttpsStatus.good
                forced_https_score = scoring.WEB_TLS_FORCED_HTTPS_GOOD
                break

    return forced_https_score, forced_https

