#!/bin/sh

set -e

cd /opt/unbound/etc/unbound/

if [ "$DEBUG_LOG_UNBOUND" = "True" ];then
  export DEBUG_LOG_UNBOUND_STATEMENTS="verbosity: 2
  log-queries: yes"
else
  export DEBUG_LOG_UNBOUND_STATEMENTS=""
fi

envsubst < unbound.conf.template > unbound.conf

# https://github.com/internetstandards/unbound/blob/internetnl/README.md#zone-signing

cd /opt/unbound/etc/unbound/zones/

if [ ! -f ns_keytag.$CONN_TEST_DOMAIN ];then
  echo "generate DNSSEC keys for $CONN_TEST_DOMAIN"
  ldns-keygen -k -a RSASHA256 test-ns-signed.$CONN_TEST_DOMAIN > ns_keytag.$CONN_TEST_DOMAIN
  ldns-keygen -k -a RSASHA256 test-ns6-signed.$CONN_TEST_DOMAIN > ns6_keytag.$CONN_TEST_DOMAIN
fi

echo "Creating signed zone files"

ns_keytag=$(cat ns_keytag.$CONN_TEST_DOMAIN)
ns6_keytag=$(cat ns6_keytag.$CONN_TEST_DOMAIN)

# interpolate config files with environment variables (domain and ip addresses)
envsubst < ../test-ns.zone.template > ../test-ns.zone
envsubst < ../test-ns6.zone.template > ../test-ns6.zone

# add DS records to zone
cat ../test-ns.zone $ns_keytag.ds > test-ns.zone
cat ../test-ns6.zone $ns6_keytag.ds > test-ns6.zone

/signzones.sh

echo "Please add the following DS records for domain $CONN_TEST_DOMAIN:"
cat /opt/unbound/etc/unbound/zones/$ns_keytag.ds
cat /opt/unbound/etc/unbound/zones/$ns6_keytag.ds

# run cron daemon for monthly zone resign
busybox crond -l7

# start unbound
/opt/unbound/sbin/unbound -d
