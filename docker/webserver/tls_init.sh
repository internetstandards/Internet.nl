# solve chickenegg problem with letsencrypt

# create initial dummy TLS certificate to allow nginx to start
if ! test -f "/etc/letsencrypt/live/$INTERNETNL_DOMAINNAME/privkey.pem";then
  mkdir -p "/etc/letsencrypt/live/$INTERNETNL_DOMAINNAME"
  openssl req -x509 -nodes -newkey rsa:4096 -days 3650 \
    -keyout "/etc/letsencrypt/live/$INTERNETNL_DOMAINNAME/privkey.pem" \
    -out "/etc/letsencrypt/live/$INTERNETNL_DOMAINNAME/fullchain.pem" \
    -subj "/CN=$INTERNETNL_DOMAINNAME"
fi