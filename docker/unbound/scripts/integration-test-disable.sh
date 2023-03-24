#!/bin/bash

set -e

mv /opt/unbound/etc/unbound/test-ns-signed.zone.bak /opt/unbound/etc/unbound/test-ns-signed.zone
mv /opt/unbound/etc/unbound/test-ns6-signed.zone.bak /opt/unbound/etc/unbound/test-ns6-signed.zone

unbound-control reload
