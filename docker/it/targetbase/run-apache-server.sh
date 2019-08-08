#!/bin/bash
set -e -u -x

WAIT_FOR_CUSTOM_COMMAND=${WAIT_FOR_CUSTOM_COMMAND:-no}
APACHE_VERSION=${APACHE_VERSION:-stock}
APACHE_MODULES=${APACHE_MODULES:-}
APACHE_SITES=${APACHE_SITES:-}

# Enable Apache modules and website configurations as directed by the user invoking Docker build
a2dissite -q 000-default
if [ "${APACHE_MODULES}" != "" ]; then for M in "${APACHE_MODULES}"; do a2enmod -q $M; done; fi
if [ "${APACHE_SITES}" != "" ]; then for S in "${APACHE_SITES}"; do a2ensite -q $S; done; fi

# Run any command defined by arguments given to this script, e.g. via
# docker-compose 'command: xxx'. Run BEFORE Apache in case this command is
# intended to prepare Apache config files or environment in some way.
if [ $# -gt 0 ]; then
    $* &>/var/log/custom-command.log &
    if [ "${WAIT_FOR_CUSTOM_COMMAND}" == "yes" ]; then
        wait $!
    fi
fi

case ${APACHE_VERSION} in
    custom-ancient)
        set +u ; . /etc/apache2/envvars ; set -u
        LD_LIBRARY_PATH=/opt/openssl-ancient/lib /opt/apache-2.2-openssl-ancient/bin/httpd -e debug -d /etc/apache2 -f /opt/apache-2.2-openssl-ancient/custom-httpd.conf
        ;;
    custom-legacy)
        set +u ; . /etc/apache2/envvars ; set -u
        /opt/apache-2.4-openssl-legacy/bin/httpd -e debug -d /etc/apache2 -f /opt/apache-2.4-openssl-legacy/custom-httpd.conf
        ;;
    custom-modern)
        set +u ; . /etc/apache2/envvars ; set -u
        LD_LIBRARY_PATH=/opt/openssl-modern/lib /opt/apache-2.4-openssl-modern/bin/httpd -e debug -d /etc/apache2 -f /opt/apache-2.4-openssl-modern/custom-httpd.conf
        ;;
    *)
        service apache2 start
esac

/usr/bin/tail -F /var/log/apache2/*.log /var/log/custom-command.log &

sleep infinity