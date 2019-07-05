#!/bin/bash
# Example usage:
#   $ gen_cipher_info.sh openssl >/tmp/ciphers.new
#   $ gen_cipher_info.sh /opt/openssl-old/bin/openssl >/tmp/ciphers.old
#   $ sort -u /tmp/ciphers.old /tmp/ciphers.new >cipher_info.csv
#   TODO: now move the CSV header row to the top of the combined file
set -euo pipefail

if [[ $# -ne 1 || $1 == *help ]]; then
    echo >&2 "Usage: $(basename $0) </path/to/bin/openssl>"
    exit 1
fi

# Convert lines like this:
#       0xC0,0x30 - ECDHE-RSA-AES256-GCM-SHA384 TLSv1.2 Kx=ECDH     Au=RSA  Enc=AESGCM(256) Mac=AEAD
# Into CSV lines like this:
#   0xC0,0x30,-,ECDHE-RSA-AES256-GCM-SHA384,TLSv1.2,ECDH,RSA,AESGCM,256,AEAD
# Where the columns are:
#   0,1 - IANA/TLS RFC Client/ServerHello cipher codes
#   2   - constant '-' which can be ignored
#   3   - IANA cipher name
#   4   - TLS protocol version
#   5   - Forward slash '/' separated key exchange algorithm(s) (e.g. DH, DH/DSS, DH/RSA)
#   6   - Authentication algorithm
#   7   - Bulk encryption algorithm (e.g. 3DES, AES, ...)
#   8   - Bulk encryption algorithm secret key length
#   9   - Message Authentication Code (hash function, e.g. AEAD, MD5, SHA1, ...)

# stdin -> stdout
openssl_ciphers_verbose_to_csv() {
    sed -e 's/^\s\+//' -e 's/[ ()]\+/,/g' -e 's/[A-Za-z]\+=//g' -e 's/,-,/,/' -e 's/,$//'
}

# arg 1: /path/to/bin/openssl
modern_cipher_dump() {
    OPENSSL=$1
    $OPENSSL ciphers -V -psk -srp ALL@SECLEVEL=0
}

# arg 1: /path/to/bin/openssl
legacy_cipher_dump() {
    OPENSSL=$1
    $OPENSSL ciphers -V
}

echo_csv_header_row() {
    echo 'major,minor,name,tls_version,kex_algs,auth_alg,bulk_enc_alg,bulk_enc_alg_sec_len,mac_alg'
}

# arg 1: /path/to/bin/openssl
# arg 2: dump function name
echo_ciphers_as_csv() {
    OPENSSL=$1
    DUMP_FUNC=$2
    $DUMP_FUNC $OPENSSL 2>/dev/null | openssl_ciphers_verbose_to_csv
}

OPENSSL=$1

echo_csv_header_row
echo_ciphers_as_csv $OPENSSL modern_cipher_dump ||
    echo_ciphers_as_csv $OPENSSL legacy_cipher_dump
