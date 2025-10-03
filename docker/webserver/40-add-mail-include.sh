#!/bin/sh

set -eu

LC_ALL=C
ME=$(basename "$0")
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

touch /etc/nginx/nginx.conf 2>/dev/null || { echo >&2 "$ME: error: can not modify /etc/nginx/nginx.conf (read-only file system?)"; exit 0; }

sed -i -r -z 's@(\}\n)$@\1# Added by '"$ME"' on '"$(date)"'\nmail {\n    include conf.d/*.mail-conf;\n}\n@' /etc/nginx/nginx.conf
