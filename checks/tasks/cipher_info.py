import re
from collections import OrderedDict
from enum import Enum
from math import log, pow

from celery.utils.log import get_task_logger
from nassl.legacy_ssl_client import LegacySslClient
from nassl.ssl_client import SslClient

from checks.tasks.tls_connection import DebugConnection, ModernConnection

logger = get_task_logger(__name__)


class SecLevel(Enum):
    GOOD = 3
    SUFFICIENT = 2
    PHASE_OUT = 1
    INSUFFICIENT = 0
    UNKNOWN = -1


class CipherScoreAndSecLevel:
    @staticmethod
    def get_subscore_key_size(ci, conn):
        return (int(ci.bulk_enc_alg_sec_len), SecLevel.UNKNOWN)

    @staticmethod
    def get_subscore_ecdsa_rsa(ci, conn):
        if ci.tls_version == "TLSv1.3":
            # negotiated, might be (2, SecLevel.GOOD) - can we check the conn
            # to find out?
            return (1, SecLevel.GOOD)
        else:
            return {
                "ECDSA": (2, SecLevel.GOOD),
                "RSA": (1, SecLevel.GOOD),
            }.get(ci.auth_alg, (0, SecLevel.INSUFFICIENT))

    @staticmethod
    def get_subscore_mac_alg(ci, conn):
        return {
            "MD5": SecLevel.INSUFFICIENT,
            "SHA1": SecLevel.SUFFICIENT,
        }.get(ci.mac_alg, SecLevel.GOOD)

    @staticmethod
    def get_subscore_aead(ci, conn):
        return {
            "AEAD": (1, SecLevel.GOOD),
        }.get(ci.mac_alg, (0, SecLevel.UNKNOWN))

    @staticmethod
    def get_subscore_ecdhe_dhe(ci, conn):
        # TODO: in TLS 1.3 the kex alg is not considered part of the cipher
        # suite and thus OpenSSL reports it as kx=any. We don't handle this
        # here.
        # Note: TLS 1.3 doesn't support RSA. TLS 1.3 is always either PSK or
        # (EC)DHE or both. See: https://tools.ietf.org/html/rfc8446#section-2
        # As we as the Internet.NL client can't use a pre-shared key with
        # the target server (as how would we get the PSK?), that leaves only
        # (EC)DHE when using TLS 1.3. We would be able to tell from the
        # connection details if it were ECDHE or DHE except that only the
        # legacy client has the necessary get_ecdh_param() function and it
        # doesn't support TLS 1.3. So we score them as good rather than
        # potentially incorrectly score them as sufficient.

        # Note: We can only score the trailing E (ephemeral) nature of the
        # communication once the handshake is complete as only then do we know
        # if the server sent a ServerKeyExchange message containing elliptic
        # curve (ECDHE) or finite field group (DHE) details to use to create an
        # ephemeral key, as opposed to getting those details from a static
        # certificate. For now we cheat and assume that if the cipher name
        # contains the extra E that means that it will be ephemeral but is this
        # a good assumption?
        DHE_TERMS = frozenset(["DHE", "EDH"])
        ECDHE_TERMS = frozenset(["ECDHE", "EECDH"])

        def contains(haystack, needles):
            # This helper method exists because with OpenSSL 1.0.2 the cipher
            # key exchange algorithms do not consistently use the terms DHE and
            # ECDHE but also use EDH and EECDH.
            # See:
            # https://www.openssl.org/docs/man1.0.2/man3/SSL_CIPHER_get_version.html
            return len([x for x in needles if x in haystack]) > 0

        if ci.tls_version == "TLSv1.3":
            # negotiated
            # could actually be (4, SecLevel.SUFFICIENT) if DHE is used instead
            # of ECDHE - can we check the conn to find out?
            return (3, SecLevel.GOOD)
        elif "ECDH" in ci.kex_algs:
            return {
                False: (2, SecLevel.INSUFFICIENT),
                True: (4, SecLevel.GOOD),
            }.get(contains(ci.name, ECDHE_TERMS))
        elif "DH" in ci.kex_algs:
            return {
                False: (1, SecLevel.INSUFFICIENT),
                True: (3, SecLevel.SUFFICIENT),
            }.get(contains(ci.name, DHE_TERMS))
        elif "RSA" in ci.kex_algs:
            return (0, SecLevel.PHASE_OUT)
        else:
            return (0, SecLevel.INSUFFICIENT)

    @staticmethod
    def get_subscore_bulk_enc_alg(ci, conn):
        if "AES" in ci.bulk_enc_alg and ci.bulk_enc_alg_sec_len == 256:
            score = 2
        elif "CHACHA20" in ci.bulk_enc_alg:
            score = 1
        else:
            score = 0

        # See: https://blog.cloudflare.com/it-takes-two-to-chacha-poly/
        if (
            (ci.bulk_enc_alg == "AESGCM" and ci.bulk_enc_alg_sec_len == 256)
            or (ci.bulk_enc_alg == "CHACHA20/POLY1305")
            or (ci.bulk_enc_alg == "AESGCM" and ci.bulk_enc_alg_sec_len == 128)
            or (ci.bulk_enc_alg == "AESCCM" and ci.bulk_enc_alg_sec_len == 256)
            or (ci.bulk_enc_alg == "AESCCM" and ci.bulk_enc_alg_sec_len == 128)
        ):
            sec_level = SecLevel.GOOD
        elif (
            (ci.bulk_enc_alg == "AES" and ci.bulk_enc_alg_sec_len == 256)
            or (ci.bulk_enc_alg == "AES" and ci.bulk_enc_alg_sec_len == 128)
            or (ci.bulk_enc_alg == "Camellia")
        ):
            sec_level = SecLevel.SUFFICIENT
        elif (
            (ci.bulk_enc_alg == "3DES")
            or (ci.bulk_enc_alg == "SEED")
            or (ci.bulk_enc_alg == "ChaCha20" and "CHACHA20-POLY1305-OLD" in ci.name)
            or (ci.bulk_enc_alg == "ARIAGCM")
        ):
            sec_level = SecLevel.PHASE_OUT
        else:
            sec_level = SecLevel.INSUFFICIENT

        return (score, sec_level)

    @staticmethod
    def get_subscore_hash_size(ci, conn):
        # Hash size is dependent on protocol version and protocol extensions.
        # SSLv2, SSLv3, TLSv1.0 and TLSv1.1 used SHA-1 which has a digest size
        # of 160-bits. TLS 1.2 introduced the SignatureAlgorithms extension
        # which made it possible to specify the hash algorithm and size, or
        # default to SHA-1 if not specified. TLS 1.3 mandates the use of the
        # SignatureAlgorithms extensions.
        if isinstance(conn, ModernConnection):
            digest = conn.get_peer_signature_digest()
        else:
            digest = None

        return {
            "SHA224": (224, SecLevel.SUFFICIENT),
            "SHA256": (256, SecLevel.GOOD),
            "SHA384": (384, SecLevel.GOOD),
            "SHA512": (512, SecLevel.GOOD),
            None: (0, SecLevel.GOOD),  # no hash func or undetermined.
        }.get(digest, (160, SecLevel.PHASE_OUT))

    @staticmethod
    def determine_appendix_c_sec_level(ci, conn=None):
        """
        Report the security level of the cipher using the same rules as used by
        'Appendix C - List of cipher suites' in the NCSC 'IT Security
        Guidelines for Transport Layer Security v2.0' document, i.e. excluding:

            'versions; hash functions for certificate verification; hash
             functions for key exchange; key sizes & choice of groups; and
             options'

        """
        counts = OrderedDict()
        counts[SecLevel.GOOD] = 0
        counts[SecLevel.SUFFICIENT] = 0
        counts[SecLevel.PHASE_OUT] = 0
        counts[SecLevel.INSUFFICIENT] = 0
        counts[SecLevel.UNKNOWN] = 0

        counts[CipherScoreAndSecLevel.get_subscore_ecdsa_rsa(ci, conn)[1]] += 1
        counts[CipherScoreAndSecLevel.get_subscore_ecdhe_dhe(ci, conn)[1]] += 1
        counts[CipherScoreAndSecLevel.get_subscore_bulk_enc_alg(ci, conn)[1]] += 1
        counts[CipherScoreAndSecLevel.get_subscore_mac_alg(ci, conn)] += 1

        # Return lowest detected security level
        for sec_level in reversed(counts.keys()):
            if counts[sec_level]:
                return sec_level

        return SecLevel.UNKNOWN

    @staticmethod
    def calc_cipher_score(ci, conn=None):
        """
        Quoting NCSC IT Security Guidelines for Transport Layer Security v2.0
        section 4 'Versions, algorithms and options' heading 'Prefer faster and
        safer algorithms':

        The NCSC advises to configure the server to prefer algorithm selections
        in the following order. This prioritizes the fastest and safest
        algorithms. Prefer Good over Sufficient over Phase out algorithm
        selections. Within a particular security level, proceed as follows.

        First, algorithms that perform key exchange based on elliptic curves
        are preferred over those that use finite fields. Both are preferred
        over algorithms that use a static key exchange.

        Second, algorithms that do bulk encryption based on AEAD algorithms are
        preferred over alternatives (see Algorithms for bulk encryption).

        Third, algorithms that do certificate verification based on ECDSA are
        preferred over RSA (though this requires the use of a certificate for
        an ECDSA key). *22

        Fourth, algorithms are preferred in descending order of their key and
        then hash size. Finally, AES-256 is preferred over ChaCha20. *33

        *22: ECDSA is preferred over RSA for performance reasons
        *23: AES is an older algorithm that has been studied for longer by the
             (academic) cryptologic community than the newer ChaCha20
             algorithm.
             AES also has a speed advantage on platforms that provide hardware
             acceleration. However, AES is less efficient than ChaCha20 on
             (mobile) platforms that lack such acceleration. Some choose to
             trade-off server performance against client battery life by
             preferring ChaCha20 over AES.

        Example scores:
            BYTE 4  BYTE 3  BYTE 2  BYTE 1  BYTE 0
            --------++++++++--------++++++++--------
            7654321076543210765432107654321076543210
                                                  AC  AES-256, ChaCha20 or REST
                                  HHHHHHHHHHHHHHHH    Hash size
                  KKKKKKKKKKKKKKKK                    Key size
                ER                                    ECDSA, RSA or REST
               A                                      AEAD or REST
            DHE                                       ECDH(E), DH(E) or REST
            E.g.
            1001010000000010000000000000010000000000  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            0001010000000010000000000000000000000000  AES128-GCM-SHA256
            0000010000000100000000000000000000000010  AES256-SHA256

        """
        return (
            (CipherScoreAndSecLevel.get_subscore_ecdhe_dhe(ci, conn)[0] << 37)
            | (CipherScoreAndSecLevel.get_subscore_aead(ci, conn)[0] << 36)
            | (CipherScoreAndSecLevel.get_subscore_ecdsa_rsa(ci, conn)[0] << 34)
            | (CipherScoreAndSecLevel.get_subscore_key_size(ci, conn)[0] << 18)
            | (CipherScoreAndSecLevel.get_subscore_hash_size(ci, conn)[0] << 2)
            | (CipherScoreAndSecLevel.get_subscore_bulk_enc_alg(ci, conn)[0])
        )

    @staticmethod
    def format_score(score):
        return format(score, "040b")

    @staticmethod
    def get_score_header():
        return "DHEAERKKKKKKKKKKKKKKKKHHHHHHHHHHHHHHHHAC"

    @staticmethod
    def is_in_seclevel_order(seclevel1, seclevel2):
        return seclevel1.value >= seclevel2.value

    @staticmethod
    def is_in_prescribed_order(score1, score2):
        if score1 is None or score2 is None:
            raise ValueError

        # TLS guidelines v2.1 (p.23): No prescribed cipher ordering within a
        # security level. For now this will simply return True. If prescribed
        # cipher ordering never returns we will remove this code in the future.
        return True

        # Ignore hash size if not set in either cipher score, as some ciphers
        # do not use a hash function and thus are not comparable by hash size
        # to a cipher that does.
        #                             DHEAERKKKKKKKKKKKKKKKKHHHHHHHHHHHHHHHHAC
        # bit_mask_only_hash_size = 0b0000000000000000000000111111111111111100

        # hash_size_1 = score1 & bit_mask_only_hash_size
        # hash_size_2 = score2 & bit_mask_only_hash_size
        # if not hash_size_1 or not hash_size_2:
        #     score1 &= ~bit_mask_only_hash_size
        #     score2 &= ~bit_mask_only_hash_size

        # return score1 >= score2

    @staticmethod
    def get_violated_rule_number(score1, score2):
        def get_highest_set_bit(n):
            return -1 if n == 0 else int(log(n, 2))

        if score1 == score2:
            raise ValueError

        # find the highest bit set in only one of the two scores, i.e. the
        # thing that most differentiates them from one another.
        highestbit = None
        while not highestbit:
            highbit1 = get_highest_set_bit(score1)
            highbit2 = get_highest_set_bit(score2)
            if highbit1 == highbit2:
                bit_mask_to_keep_only_bits_below_highbit = int(pow(2, highbit1)) - 1
                score1 &= bit_mask_to_keep_only_bits_below_highbit
                score2 &= bit_mask_to_keep_only_bits_below_highbit
            else:
                highestbit = max(highbit1, highbit2)

        # Work out which test the set bit relates to:
        if highestbit >= 37:
            # "First, algorithms that perform key exchange based on elliptic
            #  curves are preferred over those that use finite fields. Both
            #  are preferred over algorithms that use a static key exchange."
            return 1
        elif highestbit >= 36:
            # "Second, algorithms that do bulk encryption based on AEAD
            #  algorithms are preferred over alternatives"
            return 2
        elif highestbit >= 34:
            # "Third, algorithms that do certificate verification based
            #  on ECDSA are preferred over RSA"
            return 3
        elif highestbit >= 2:
            # "Fourth, algorithms are preferred in descending order of their
            #  key and then hash size"
            return 4
        else:
            # "Finally, AES-256 is preferred over ChaCha20.2"
            return 5


# Load OpenSSL data about cipher suites
def load_cipher_info():
    return {}

    class CipherInfo:
        def __init__(self, conn_class, match):
            self.conn_class = conn_class
            self.name = match.group("name")
            self.tls_version = match.group("tls_version")
            self.kex_algs = match.group("kex_algs")
            self.auth_alg = match.group("auth_alg")
            self.bulk_enc_alg = match.group("bulk_enc_alg")
            self.mac_alg = match.group("mac_alg")

            if match.group("bulk_enc_alg_sec_len"):
                self.bulk_enc_alg_sec_len = int(match.group("bulk_enc_alg_sec_len"))
            else:
                self.bulk_enc_alg_sec_len = 0

    # See: https://regex101.com/r/VPpuN4/2
    CIPHER_DESC_REGEX = re.compile(
        r"(?P<name>[^\s]+)"
        r"\s+(?P<tls_version>[^\s]+)"
        r"\s+Kx=(?P<kex_algs>[^\s(]+(\((?P<unknown>[0-9]+)\))?)"
        r"\s+Au=(?P<auth_alg>[^\s]+)"
        r"\s+Enc=(?P<bulk_enc_alg>[^\s(]+)(\((?P<bulk_enc_alg_sec_len>[0-9]+)\))?"
        r"\s+Mac=(?P<mac_alg>[^\s]+)"
    )

    result = dict()
    for client_class, conn_class in [
        (LegacySslClient, DebugConnection),
        (SslClient, ModernConnection),
    ]:
        c = client_class()
        if client_class == SslClient:
            c.set_cipher_list(ModernConnection.ALL_CIPHERS)
        else:
            c.set_cipher_list(DebugConnection.ALL_CIPHERS)
        for cipher_name in c.get_cipher_list():
            if cipher_name not in result:
                desc = c.get_cipher_description(cipher_name)
                match = CIPHER_DESC_REGEX.match(desc)
                if match:
                    ci = CipherInfo(conn_class, match)

                    # Pre-calculate the security level as it, currently,
                    # doesn't depend on a current connection.
                    ci.sec_level = CipherScoreAndSecLevel.determine_appendix_c_sec_level(ci)

                    # Record the connection class so that we can later use
                    # only supported ciphers with a particular connection
                    # class.
                    ci.supported_conns = {conn_class}

                    result[cipher_name] = ci
                else:
                    logger.warn(
                        f"Unable to parse description of cipher {cipher_name} "
                        f'output by {client_class.__name__}: "{desc}"'
                    )
            else:
                # Add this connection class to the set of supported connection
                # classes.
                result[cipher_name].supported_conns.add(conn_class)

    return result


cipher_infos = load_cipher_info()
logger.info(f'Loaded data on {len(cipher_infos)} ciphers."')
