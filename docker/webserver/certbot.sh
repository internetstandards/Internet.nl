#!/usr/bin/env sh

set -x

# request initial TLS certificates from letsencrypt

if [ $LETSENCRYPT_STAGING != "0" ]; then
  staging="--staging"
fi

if [ ! -z $LETSENCRYPT_EMAIL ]; then
  email="--email=$LETSENCRYPT_EMAIL"
else
  email="--register-unsafely-without-email"
fi

if [ ! -z $CERTBOT_SERVER ]; then
  server="--server=$CERTBOT_SERVER"
fi


if [ ! -z $CERTBOT_EAB_KID ]; then
  eab_kid="--eab-kid=$CERTBOT_EAB_KID"
fi

if [ ! -z $CERTBOT_EAB_HMAC_KEY ]; then
  eab_hmac_key="--eab-hmac-key=$CERTBOT_EAB_HMAC_KEY"
fi

domain=$INTERNETNL_DOMAINNAME
subdomains="nl.$domain,en.$domain,www.$domain,ipv6.$domain,conn.$domain,en.conn.$domain,nl.conn.$domain,www.conn.$domain"
if [ ! -z $REDIRECT_DOMAINS ];then
  subdomains="$subdomains,$REDIRECT_DOMAINS"
fi

# configure the main domain and the subdomains in 2 steps. This makes sure a cert for the main domain is always created
# even if the subdomains are not configured.
configure_letsencrypt() {
  # skip if already configured
  if [ ! -f /etc/letsencrypt/renewal/$domain.conf ]; then

    # move temporary self signed cert out of the way
    mv /etc/letsencrypt/live/$domain /etc/letsencrypt/live/$domain.bak

    # request new certificate for main domain
    /opt/certbot/bin/certbot certonly --webroot \
      -n \
      --webroot-path /var/www/internet.nl \
      --rsa-key-size 4096 \
      --agree-tos \
      --force-renewal \
      --post-hook "nginx -s reload" \
      --webroot \
      $staging \
      $email \
      $server \
      $eab_kid \
      $eab_hmac_key \
      --cert-name $domain \
      -d $domain
    cert_acquired=$?

    if [ $cert_acquired -eq 0 ];then
      # remove temporary self signed cert
      rm -rf /etc/letsencrypt/live/$domain.bak
    else
      # move self signed certificate back
      mv /etc/letsencrypt/live/$domain.bak /etc/letsencrypt/live/$domain
    fi
  fi

  # update certificate with subdomains if domain is configured and subdomains have changed or are not configured yet
  if [ -f /etc/letsencrypt/renewal/$domain.conf ] && [ ! "$(cat /etc/letsencrypt/.subdomains-configured)" = "$subdomains" ]; then
    # request new certificate for subdomains as well, but in a seperate step so we
    # don't fail if they are not properly setup
    /opt/certbot/bin/certbot certonly --webroot \
      -n \
      --webroot-path /var/www/internet.nl \
      --rsa-key-size 4096 \
      --agree-tos \
      --force-renewal \
      --post-hook "nginx -s reload" \
      --webroot \
      $staging \
      $email \
      $server \
      $eab_kid \
      $eab_hmac_key \
      --cert-name $domain \
      -d $domain \
      -d $subdomains \
      --expand
    cert_acquired=$?

    if [ $cert_acquired -eq 0 ];then
      # create file indicating (all new) subdomains are configured
      echo "$subdomains" > "/etc/letsencrypt/.subdomains-configured"
    fi
  fi
}

# delay certificate request in background because nginx needs to be up when starting letsencrypt configuration
(sleep 1m; configure_letsencrypt)&

# check certificates for renewal twice a day, make sure the schedule is a moving window so we
# don't accidentally fall in line with the busiest time (eg: 00:00) and get errors due to ACME
# servers being overloaded at that moment
while sleep 11h; do certbot renew --post-hook "nginx -s reload"; done&
