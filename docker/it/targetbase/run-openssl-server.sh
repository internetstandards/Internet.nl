#!/bin/bash
set -e -u

# Keys and certificates used to secure communication
KEY="/etc/ssl/private/wildcard.test.nlnetlabs.nl.key"
CERT="/etc/ssl/certs/wildcard.test.nlnetlabs.nl.crt"
CA_CERT="/opt/ca-ocsp/ca/rootCA.crt"

# Old OpenSSL s_server cannot listen on IPv6 at all. New OpenSSL can listen on
# IPv4 or IPv6 but not both. Use SOCAT to forward IPv6 to IPv4 to work around
# this limitation.
socat TCP6-LISTEN:443,fork TCP4:127.0.0.1:4433 &

# New OpenSSL doesn't support the old SSLv2 and SSLv3 protocols, an old
# version of OpenSSL is required for that. Old OpenSSL doesn't have an option
# for disabling renegotiation.
OPENSSL=openssl
RENEG_OPT=" -no_renegotiation"
if echo $* | grep -qE -- '-ssl(2|3)'; then
    OPENSSL=/opt/openssl-old/bin/openssl
    RENEG_OPT=
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

# Pass any given arguments to OpenSSL
${OPENSSL_CMD} $*

