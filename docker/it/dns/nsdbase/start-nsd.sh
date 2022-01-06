#!/bin/bash
set -e

# Configure the SLAVE_EXCLUDE env var which jinjify (below) will replace in the nsd.conf
case ${ROLE} in
    slave)
        export MASTER_EXCLUDE='#'
        export SLAVE_EXCLUDE=
        export SLAVE_IP=UNSET
        export PRIMARY_IP=${OTHER_IP}
        ;;

    master)
        export MASTER_EXCLUDE=
        export SLAVE_EXCLUDE='#'
        export SLAVE_IP=${OTHER_IP}
        export PRIMARY_IP=UNSET
        ;;

    *)
        # slaveless master
        export MASTER_EXCLUDE='#'
        export SLAVE_EXCLUDE='#'
        export PRIMARY_IP=UNSET
        export SLAVE_IP=UNSET
        ;;
esac

set -u

# replace Jinja2 markup in config files
/opt/jinjify.sh /etc/nsd

# generate certificate files
nsd-control-setup

# run NSD in the foreground
nsd-control start
tail -n 1000 -F /tmp/nsd.log