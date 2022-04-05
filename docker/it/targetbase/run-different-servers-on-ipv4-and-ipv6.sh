#!/bin/bash
set -e -u

# Keys and certificates used to secure communication
KEY="/etc/ssl/private/wildcard.test.nlnetlabs.nl.key"
CERT="/etc/ssl/certs/wildcard.test.nlnetlabs.nl.crt"
CA_CERT="/opt/ca-ocsp/ca/rootCA.crt"

OPENSSL=openssl
RENEG_OPT=" -no_renegotiation"

# Build the OpenSSL command to run:
OPENSSL_CMD="${OPENSSL}"
OPENSSL_CMD="${OPENSSL_CMD} s_server"           # run a server listening for
OPENSSL_CMD="${OPENSSL_CMD} -accept 443"        # connections on port 4433
OPENSSL_CMD="${OPENSSL_CMD} -key ${KEY}"        # use this key
OPENSSL_CMD="${OPENSSL_CMD} -cert ${CERT}"      # use this certificate
OPENSSL_CMD="${OPENSSL_CMD} -CAfile ${CA_CERT}" # chain this root CA cert
OPENSSL_CMD="${OPENSSL_CMD} -status"            # include OCSP in the response
OPENSSL_CMD="${OPENSSL_CMD} -www"               # run a simple web server
OPENSSL_CMD="${OPENSSL_CMD}${RENEG_OPT}"        # try to disable renegotiation

OPENSSL_CMD_V4="${OPENSSL_CMD} -4 -tls1_2"      # listen on different protocols
OPENSSL_CMD_V6="${OPENSSL_CMD} -6 -tls1_3"      # to make the -www output differ

echo -n "OpenSSL version: "; ${OPENSSL} version

echo "Running OpenSSL with command: ${OPENSSL_CMD_V4} $*"
${OPENSSL_CMD_V4} $* &

echo "Running OpenSSL with command: ${OPENSSL_CMD_V6} $*"
${OPENSSL_CMD_V6} $* &

sleep infinity