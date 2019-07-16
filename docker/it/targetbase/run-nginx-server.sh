#!/bin/bash
set -e -u -x

if [ $# -ne 1 ]; then
    echo >&2 "ERROR: No nginx config file path specified."
    exit 1
fi

perl -pi -e 's|error_log /var/log/nginx/error.log|error_log /var/log/nginx/error.log debug|' /etc/nginx/nginx.conf

cd /etc/nginx/sites-enabled
rm -f default
ln -s $1

# Work around error: "ssl_stapling" ignored, host not found in OCSP responder
# "ca-ocsp.test.nlnetlabs.tk:8080" in the certificate "/etc/ssl/certs/xxx.crt"
while ! host ca-ocsp.test.nlnetlabs.tk; do
    sleep 1s
done

# Fetch the OCSP responder certificate rather than have NGINX contact the
# responder. This is because NGINX doesn't pre-fetch the responder cert and
# so can reply to clients without an OCSP stapled response, which we don't
# want.
# See: https://blog.apnic.net/2019/01/15/is-the-web-ready-for-ocsp-must-staple/
# See: https://raymii.org/s/articles/OpenSSL_Manually_Verify_a_certificate_against_an_OCSP.html
OCSP_RESPONDER_URI=$(openssl x509 -noout -ocsp_uri -in /etc/ssl/certs/wildcard.test.nlnetlabs.tk.crt)
openssl ocsp \
    -issuer /opt/ca-ocsp/ca/rootCA.crt \
    -CAfile /opt/ca-ocsp/ca/rootCA.crt \
    -cert /etc/ssl/certs/wildcard.test.nlnetlabs.tk.crt \
    -url ${OCSP_RESPONDER_URI} \
    -respout /etc/ssl/certs/ocsp_responses/wildcard.test.nlnetlabs.tk.der

# The NGINX config references the above created .der file.
service nginx restart

tail -n 1000 -F /var/log/nginx/*.log