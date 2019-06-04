#!/bin/bash
set -e -u

# replace Jinja2 markup in config files
/opt/jinjify.sh /etc/unbound

# generate certificate files
unbound-control-setup

# run Unbound in the foreground
#unbound -d || cat /tmp/unbound.log

unbound-control start
tail -n 1000 -F /tmp/unbound.log