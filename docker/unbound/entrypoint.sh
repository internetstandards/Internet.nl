#!/bin/sh

set -e

envsubst < test-ns-signed.zone.template > test-ns-signed.zone
envsubst < test-ns6-signed.zone.template > test-ns6-signed.zone
cp unbound.conf unbound.conf~
envsubst < unbound.conf~ > unbound.conf

/opt/unbound/sbin/unbound -d
