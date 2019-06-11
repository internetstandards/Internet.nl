#!/bin/bash
set -e -u -x

service apache2 start

/usr/bin/tail -F /var/log/apache2/*.log /var/log/custom-server.log &

if [ $# -gt 0 ]; then
    $* &>/var/log/custom-server.log
fi

sleep infinity