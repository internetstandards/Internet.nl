#!/bin/bash
set -e -u -x

if [ $# -ne 1 ]; then
    echo >&2 "ERROR: No nginx config file path specified."
    exit 1
fi

perl -pi -e 's|error_log /var/log/nginx/error.log|error_log /var/log/nginx/error.log debug|' /etc/nginx/nginx.conf

rm /etc/nginx/sites-enabled/default
mv $1 /etc/nginx/sites-enabled/
service nginx restart

tail -n 1000 -F /var/log/nginx/*.log