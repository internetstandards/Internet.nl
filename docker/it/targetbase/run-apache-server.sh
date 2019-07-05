#!/bin/bash
set -e -u -x

service apache2 start

if [ $# -gt 0 ]; then
    $* &>/var/log/custom-server.log &
fi

/usr/bin/tail -F /var/log/apache2/*.log /var/log/custom-server.log &

sleep infinity