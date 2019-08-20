#!/bin/bash
set -e -u -x

WAIT_FOR_CUSTOM_COMMAND=${WAIT_FOR_CUSTOM_COMMAND:-no}
NGINX_SITES=${NGINX_SITES:-}
POSTFIX_VERSION=${POSTFIX_VERSION:-}
POSTFIX_CONFIG=${POSTFIX_CONFIG:-}

perl -pi -e 's|error_log /var/log/nginx/error.log|error_log /var/log/nginx/error.log debug|' /etc/nginx/nginx.conf

cd /etc/nginx/sites-enabled
rm -f default
for SITE in ${NGINX_SITES}; do
    ln -s /etc/apache2/sites-available/${SITE}.conf
done

# Work around error: "ssl_stapling" ignored, host not found in OCSP responder
# "ca-ocsp.test.nlnetlabs.tk:8080" in the certificate "/etc/ssl/certs/xxx.crt"
while ! host ca-ocsp.test.nlnetlabs.tk; do
    sleep 1s
done

# Run any command defined by arguments given to this script, e.g. via
# docker-compose 'command: xxx'. Run BEFORE Apache in case this command is
# intended to prepare Apache config files or environment in some way.
if [ $# -gt 0 ]; then
    $* &>/var/log/custom-command.log &
    if [ "${WAIT_FOR_CUSTOM_COMMAND}" == "yes" ]; then
        wait $!
    fi
fi

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

# Start postfix
case ${POSTFIX_VERSION} in
    custom-legacy)
        cat /etc/postfix/configs-available/${POSTFIX_CONFIG}.cf >>/opt/postfix-old/etc/main.cf
        /opt/postfix-old/bin/postfix start
        ;;
    custom-modern)
        cat /etc/postfix/configs-available/${POSTFIX_CONFIG}.cf >>/opt/postfix-modern/etc/main.cf
        /opt/postfix-modern/bin/postfix start
        ;;
esac

tail -F /var/log/nginx/*.log /var/log/postfix /var/log/custom-command.log &

sleep infinity