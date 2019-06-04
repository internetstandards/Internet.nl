#!/bin/bash
set -e -u

service apache2 start

/usr/bin/tail -F /var/log/apache2/*.log