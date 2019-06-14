#!/bin/bash
set -e -u

# Setup based on: https://medium.com/@bhashineen/create-your-own-ocsp-server-ffb212df8e63

cd /opt/ca-ocsp
openssl ocsp \
    -index ca/index.txt \
    -port 8080 \
    -rsigner ocsp/ocspSigning.crt \
    -rkey ocsp/ocspSigning.key \
    -CA ca/rootCA.crt \
    -text \
    -multi 10 \
    -out /var/log/ocsp.log &

tail -n 9999 -F /var/log/ocsp.log