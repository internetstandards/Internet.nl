#!/bin/bash
set -e -u -x

if [ $# -ne 1 ]; then
    echo >&2 "ERROR: No nginx config file path specified."
    exit 1
fi

perl -pi -e 's|error_log /var/log/nginx/error.log|error_log /var/log/nginx/error.log debug|' /etc/nginx/nginx.conf

rm /etc/nginx/sites-enabled/default
mv $1 /etc/nginx/sites-enabled/

# Work around error: "ssl_stapling" ignored, host not found in OCSP responder "ca-ocsp.test.nlnetlabs.nl:8080" in the certificate "/etc/ssl/certs/xxx.crt"
while ! host ca-ocsp.test.nlnetlabs.nl; do
    sleep 1s
done

service nginx restart

tail -n 1000 -F /var/log/nginx/*.log