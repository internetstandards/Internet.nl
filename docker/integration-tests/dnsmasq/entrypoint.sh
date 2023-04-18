#!/bin/sh

set -e

cat >/etc/dnsmasq.d/connection-test.conf <<EOF
address=/$INTERNETNL_DOMAINNAME/$IPV4_WEBSERVER_IP_PUBLIC
address=/$TEST_TARGET_DOMAINNAME/$IPV4_IP_TEST_TARGET_PUBLIC
address=/$TEST_TARGET_DOMAINNAME/$IPV6_IP_TEST_TARGET_PUBLIC
address=/mx.target.test/$IPV4_IP_TEST_TARGET_MAIL_PUBLIC
address=/mx.target.test/$IPV6_IP_TEST_TARGET_MAIL_PUBLIC
address=/invalid-domain.example.com/
server=/test-ns-signed.$INTERNETNL_DOMAINNAME/$IPV4_IP_UNBOUND_INTERNAL
server=/test-ns6-signed.$INTERNETNL_DOMAINNAME/$IPV4_IP_UNBOUND_INTERNAL
txt-record=0.43.172.origin.asn.cymru.com,"21928 | 172.32.0.0/11 | US | arin | 2012-09-18"
txt-record=1.0.0.0.3.4.0.0.0.0.d.f.origin6.asn.cymru.com,""
mx-host=target.test,mx.target.test,10
address=/cert-valid.ris.ripe.net/93.175.146.1
address=/cert-valid.ris.ripe.net/2001:7fb:fd02::1
address=/cert-bad-origin.ris.ripe.net/93.175.147.1
address=/cert-bad-origin.ris.ripe.net/2001:7fb:fd03::1
address=/cert-none.ris.ripe.net/84.205.83.1
address=/cert-none.ris.ripe.net/2001:7fb:ff03::1
log-queries
log-facility=-
# don't forward resolving to speed up tests
no-resolv
EOF

dnsmasq -k
