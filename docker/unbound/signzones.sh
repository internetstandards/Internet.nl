#!/bin/sh

# This script is called during container start by /entrypoint.sh or weekly via symlink in /etc/periodic/weekly/

set -e

cd /opt/unbound/etc/unbound/zones/

ns_keytag=$(cat ns_keytag.$CONN_TEST_DOMAIN)
ns6_keytag=$(cat ns6_keytag.$CONN_TEST_DOMAIN)

echo "Signing zone files"

# sign zones
ldns-signzone -u -n -o test-ns-signed.$CONN_TEST_DOMAIN test-ns.zone $ns_keytag
ldns-signzone -u -n -o test-ns6-signed.$CONN_TEST_DOMAIN test-ns6.zone $ns6_keytag

# make bogus record
sed -ie '/bogus.*IN\tRRSIG/d' test-ns.zone.signed
sed -ie '/bogus.*IN\tRRSIG/d' test-ns6.zone.signed

# reload unbound if called from cron
if pgrep unbound >/dev/null; then
    echo "Reloading unbound"
    unbound-control reload
fi
