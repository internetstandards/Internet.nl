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

envsubst < "$config_file.template" > "$config_file"

/opt/unbound/sbin/unbound -d -c "/opt/unbound/etc/unbound/$config_file"
