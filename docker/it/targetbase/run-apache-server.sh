#!/bin/bash
set -e -u -x

if [ "${APACHE_WITH_LEGACY_OPENSSL}" == "yes" ]; then
    set +u ; . /etc/apache2/envvars ; set -u
    /opt/custom-httpd/bin/httpd -e debug -d /etc/apache2 -f /opt/custom-httpd/custom-httpd.conf
else
    service apache2 start
fi

if [ $# -gt 0 ]; then
    $* &>/var/log/custom-server.log &
fi

/usr/bin/tail -F /var/log/apache2/*.log /var/log/custom-server.log &

sleep infinity