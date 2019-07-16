#!/bin/bash
set -e -u -x

WAIT_FOR_CUSTOM_COMMAND=${WAIT_FOR_CUSTOM_COMMAND:-no}
APACHE_WITH_LEGACY_OPENSSL=${APACHE_WITH_LEGACY_OPENSSL:-no}

# Run any command defined by arguments given to this script, e.g. via
# docker-compose 'command: xxx'. Run BEFORE Apache in case this command is
# intended to prepare Apache config files or environment in some way.
if [ $# -gt 0 ]; then
    $* &>/var/log/custom-command.log &
    if [ "${WAIT_FOR_CUSTOM_COMMAND}" == "yes" ]; then
        wait $!
    fi
fi

if [ "${APACHE_WITH_LEGACY_OPENSSL}" == "yes" ]; then
    set +u ; . /etc/apache2/envvars ; set -u
    /opt/custom-httpd/bin/httpd -e debug -d /etc/apache2 -f /opt/custom-httpd/custom-httpd.conf
else
    service apache2 start
fi

/usr/bin/tail -F /var/log/apache2/*.log /var/log/custom-command.log &

sleep infinity