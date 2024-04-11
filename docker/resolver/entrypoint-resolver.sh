#!/bin/sh

set -e

cd /opt/unbound/etc/unbound/

if [ "$DEBUG_LOG_UNBOUND" = "True" ];then
  export DEBUG_LOG_UNBOUND_STATEMENTS="verbosity: 2
  log-queries: yes"
else
  export DEBUG_LOG_UNBOUND_STATEMENTS=""
fi

config_file="${1?"Config file not specified"}"

DNS_CACHE_TTL=$(echo "0.9 $INTERNETNL_CACHE_TTL" | awk '{printf "%d",$1*$2}')
export DNS_CACHE_TTL

envsubst < "$config_file.template" > "$config_file"

/opt/unbound/sbin/unbound -d -c "/opt/unbound/etc/unbound/$config_file"
