#!/usr/bin/env sh

HTPASSWD_FILE="/etc/nginx/htpasswd/external/users.htpasswd"

if [ ! -f "$HTPASSWD_FILE" ]; then
  touch "$HTPASSWD_FILE"
fi

if [ "$1" = "add_update" ]; then
  /usr/bin/htpasswd -B "$HTPASSWD_FILE" "$2"
  /usr/sbin/nginx -s reload
elif [ "$1" = "remove" ]; then
  /usr/bin/htpasswd -D "$HTPASSWD_FILE" "$2"
  /usr/sbin/nginx -s reload
elif [ "$1" = "verify" ]; then
  /usr/bin/htpasswd -v "$HTPASSWD_FILE" "$2"
else
  echo "Usage: user_manage.sh <add_update|remove|verify> <username>"
  exit 1
fi
