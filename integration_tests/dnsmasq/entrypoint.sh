#!/bin/sh

set -e

cat >/etc/dnsmasq.d/connection-test.conf <<EOF
address=/internet.nl/192.0.2.1
server=/test-ns-signed.internet.nl/$IPV4_IP_UNBOUND_INTERNAL
server=/test-ns6-signed.internet.nl/$IPV4_IP_UNBOUND_INTERNAL
txt-record=0.43.172.origin.asn.cymru.com,"21928 | 172.32.0.0/11 | US | arin | 2012-09-18"
txt-record=1.0.0.0.3.4.0.0.0.0.d.f.origin6.asn.cymru.com,""
mx-host=test-target.internet.nl,mx.test-target.internet.nl,10
log-queries
log-facility=-
EOF

dnsmasq -k