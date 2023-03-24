#!/bin/sh

set -e

cat >/etc/dnsmasq.d/connection-test.conf <<EOF
server=/test-ns-signed.internet.nl/$IPV4_IP_UNBOUND_INTERNAL
server=/test-ns6-signed.internet.nl/$IPV4_IP_UNBOUND_INTERNAL
mx-host=test-target.internet.nl,mx.test-target.internet.nl,10
log-queries
EOF

dnsmasq -k