#!/bin/sh

set -e

echo "Define servername ${INTERNETNL_DOMAINNAME}" > sites-enabled/00_variables.conf
echo "Define ipv6_test_addr ${IPV6_TEST_ADDR}" >> sites-enabled/00_variables.conf
test -f /etc/acme/certs/cert.pem && echo "Define enable_tls true" >> sites-enabled/00_variables.conf

httpd-foreground -c"Include /usr/local/apache2/sites-enabled/*.conf" "$@"
