#!/bin/sh

# because mail "server" directives need to go into a "mail" block and normal templates are always included
# in the "http" block we make an exception here for mail server templates.

set -eu

# apply variable substitution to mail templates
export NGINX_ENVSUBST_TEMPLATE_DIR="/etc/nginx/mail_templates"
export NGINX_ENVSUBST_OUTPUT_DIR="/etc/nginx/conf-mail.d/"
mkdir -p "$NGINX_ENVSUBST_OUTPUT_DIR"
/docker-entrypoint.d/20-envsubst-on-templates.sh

# include mail templates into config file
cat >> /etc/nginx/nginx.conf <<EOF
mail {
  include conf-mail.d/*.conf;
}
EOF
