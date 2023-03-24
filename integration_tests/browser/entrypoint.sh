#!/bin/sh

set -e -o pipefail

# TODO: fetch from env
echo "nameserver 192.168.32.12" > /etc/resolv.conf

sleep infinity