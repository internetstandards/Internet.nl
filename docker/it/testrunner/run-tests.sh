#!/bin/bash
# This script performs post deployment setup tasks on the root, master and resolver servers
# in the cluster created by docker-compose up.

set -e -u

wait_for_container_up() {
    CONTAINER_NAME="$1"
    SECONDS_TO_WAIT=${2:-15}
    echo -n "Waiting ${SECONDS_TO_WAIT} seconds for Docker container ${CONTAINER_NAME} to be up: "
    while [[ ${SECONDS_TO_WAIT} -ge 1 && -z $( docker ps --filter "status=running" --format "{{.Names}}" --no-trunc | grep ${CONTAINER_NAME}) ]]; do
        echo -n .
        sleep 1s
        let "SECONDS_TO_WAIT=SECONDS_TO_WAIT-1"
    done
    echo '. up'
}

echo
echo ':: Signing test.nlnetlabs.nl..'
wait_for_container_up submaster
docker exec submaster /opt/nsd-sign-zone.sh test.nlnetlabs.nl test.nlnetlabs.nl nlnetlabs.nl nlnetlabs.nl submaster

echo
echo ':: Signing nlnetlabs.nl..'
wait_for_container_up master
docker exec submaster /opt/nsd-sign-zone.sh nlnetlabs.nl nlnetlabs.nl nl nl master

echo
echo ':: Signing nl..'
wait_for_container_up root
docker exec master /opt/nsd-sign-zone.sh nl nl . root root

echo
echo ':: Signing the root..'
docker exec root /opt/nsd-sign-zone.sh . root

echo
echo ':: Retrieving root trust anchor for use by the resolver..'
# Not sure why docker cp root:/tmp/zsk.key /tmp/root_zsk.key doesn't work...
docker exec root cat /tmp/zsk.key >/tmp/root_zsk.key

echo
echo ':: Installing root trust anchor in the resolver..'
wait_for_container_up resolver
docker cp /tmp/root_zsk.key resolver:/var/lib/unbound/my-root.key
docker exec resolver perl -pi -e 's|^#   auto-trust-anchor-file:.+|   auto-trust-anchor-file: "/var/lib/unbound/my-root.key"|' /etc/unbound/unbound.conf
docker exec resolver unbound-control reload

echo
echo ':: Verify DNS lookup from resolver -> master -> root with DNSSEC'
dig +dnssec @${RESOLVER_IP} tls1213.test.nlnetlabs.nl

echo
echo ':: Checking DNSSEC trust tree'
docker exec resolver drill @127.0.0.1 SOA IN -DSk /var/lib/unbound/my-root.key -r /etc/unbound/root.hints tls1213.test.nlnetlabs.nl

echo
echo ':: Installing root trust anchor in the app..'
docker cp /tmp/root_zsk.key app:/tmp/root_zsk.key

PROTOCOLS="tls1 tls1_1 tls1_2"
TARGETS="nossl tls1213 tls1213sni tls1213wrongcertname tls1213nohsts tls12only tls11only"
SUFFIX=".test.nlnetlabs.nl"

echo
echo ':: Dumping target domain SSL cert to hostname mappings'
for N in ${TARGETS}; do
    echo -n -e "$N:\t"
    FQDN="${N}${SUFFIX}"
    openssl s_client -showcerts -verify_return_error -brief ${FQDN}:443 2>&1 | grep -Eo "CN = .+" || echo ERROR
done | column -t

echo
echo ':: Dumping target domain SSL version support'
for N in $TARGETS; do
    FQDN="${N}${SUFFIX}"
    echo -n "${N}: "
    for PROT in ${PROTOCOLS}; do
        echo -n "${PROT}: "
        SUPPORTED='-'
        echo GET / | openssl s_client -${PROT} -servername ${FQDN} -connect ${FQDN}:443 &>/dev/null && SUPPORTED='YES'
        echo -n -e "${SUPPORTED}\t"
    done
    echo
done | column -t

echo
echo ':: Waiting for Internet.nl app to become available..'
wait_for_container_up app
echo -n "Attempting to connect: "
while ! nc -z app 8080; do
  echo -n .
  sleep 1s
done
echo

# TODO: sleeps are brittle, replace this with a deterministic check
echo
echo ':: Wait 15 seconds to give the app time to settle, e.g. Celery worker startup etc..'
sleep 15s

echo
echo ':: Execute the browser based integration test suite..'

PYTEST_PROGRESS_ARGS="--show-progress"
PYTEST_SELENIUM_ARGS="--driver Remote --host selenium --port 4444 --capability browserName firefox"
PYTEST_HTML_ARGS="--html=/tmp/it-report/$(date +'%Y%m%d_%H%M%S').html"

docker exec app sudo mkdir -p /tmp/it-report/coverage-data
docker exec app sudo chmod -R a+w /tmp/it-report
docker exec app pytest \
    ${PYTEST_PROGRESS_ARGS} \
    ${PYTEST_HTML_ARGS} \
    ${PYTEST_SELENIUM_ARGS} || true

docker exec app /opt/coverage-finalize.sh