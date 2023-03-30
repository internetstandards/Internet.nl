#!/bin/sh

set -e -o pipefail

# TODO: fetch from env
echo "nameserver $IPV4_IP_RESOLVER_INTERNAL" > /etc/resolv.conf

sleep infinity