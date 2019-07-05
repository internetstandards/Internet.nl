#!/bin/bash
set -e -u

OPENSSL=openssl
OLD_OPENSSL=/opt/openssl-old/bin/openssl
USE_OLD_OPENSSL=0

if [[ $# -ge 1 && "$1" == "--use-old-openssl" ]]; then
    USE_OLD_OPENSSL=1
    shift
fi

# Keys and certificates used to secure communication
KEY="/etc/ssl/private/wildcard.test.nlnetlabs.nl.key"
CERT="/etc/ssl/certs/wildcard.test.nlnetlabs.nl.crt"
CA_CERT="/opt/ca-ocsp/ca/rootCA.crt"

# Old OpenSSL s_server cannot listen on IPv6 at all. New OpenSSL can listen on
# IPv4 or IPv6 but not both. Use SOCAT to forward IPv6 to IPv4 to work around
# this limitation.
echo "Using socat to forward connections from port 443 to port 4433"
socat TCP6-LISTEN:443,fork TCP4:127.0.0.1:4433 &

if echo $* | grep -qE -- '-ssl(2|3)'; then
    if [ $USE_OLD_OPENSSL -eq 0 ]; then
        echo "Forcing use of old OpenSSL because requested SSLv2/SSLv3 is not suppported by modern OpenSSL"
        USE_OLD_OPENSSL=1
    fi
fi

RENEG_OPT=
if [ $USE_OLD_OPENSSL -eq 1 ]; then
    OPENSSL=${OLD_OPENSSL}
else
    # Only modern OpenSSL supports disabling renegotiation.
    RENEG_OPT=" -no_renegotiation"
fi

# Build the OpenSSL command to run:
OPENSSL_CMD="${OPENSSL}"
OPENSSL_CMD="${OPENSSL_CMD} s_server"           # run a server listening for
OPENSSL_CMD="${OPENSSL_CMD} -accept 4433"       # connections on port 4433
OPENSSL_CMD="${OPENSSL_CMD} -key ${KEY}"        # use this key
OPENSSL_CMD="${OPENSSL_CMD} -cert ${CERT}"      # use this certificate
OPENSSL_CMD="${OPENSSL_CMD} -CAfile ${CA_CERT}" # chain this root CA cert
OPENSSL_CMD="${OPENSSL_CMD} -www"               # act as a simple HTTP server
OPENSSL_CMD="${OPENSSL_CMD} -status"            # include OCSP in the response
OPENSSL_CMD="${OPENSSL_CMD}${RENEG_OPT}"        # try to disable renegotiation

echo "Running OpenSSL with command: ${OPENSSL_CMD} $*"
echo -n "OpenSSL version: "; ${OPENSSL} version

# Pass any given arguments to OpenSSL
${OPENSSL_CMD} $*
