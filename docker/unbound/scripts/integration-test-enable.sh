#!/bin/bash

set -e

APP_NAME=app
APP_IP_ORIG=185.49.141.11
APP_IP_DOCKER=$(getent ahostsv4 $APP_NAME|grep RAW|cut -d\  -f1)
APP_IP6_ORIG=2a04:b900:0:100::11
APP_IP6_DOCKER=$(getent ahostsv6 $APP_NAME|grep RAW|cut -d\  -f1)

cp /opt/unbound/etc/unbound/test-ns-signed.zone /opt/unbound/etc/unbound/test-ns-signed.zone.bak
cp /opt/unbound/etc/unbound/test-ns6-signed.zone /opt/unbound/etc/unbound/test-ns6-signed.zone.bak
sed -iE "s/$APP_IP_ORIG/$APP_IP_DOCKER/" /opt/unbound/etc/unbound/*.zone
sed -iE "s/$APP_IP6_ORIG/$APP_IP6_DOCKER/" /opt/unbound/etc/unbound/*.zone

unbound-control reload
