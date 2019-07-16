#!/bin/bash
# This script performs post deployment setup tasks on the root, master and resolver servers
# in the cluster created by docker-compose up.
# This script expects environment variable COMPOSE_PROJECT_NAME to be set. The intention is
# that it is passed in by the docker-compose.yml file, e.g.:
#   environment:
#     - COMPOSE_PROJECT_NAME
# and also used when invoking docker-compose, e.g.
#   COMPOSE_PROJECT_NAME=blah docker-compose up
# This will result in container names being prefixed by COMPOSE_PROJECT_NAME. Otherwise the
# default is 'it', as that is the directory the integration test docker-compose.yml file is
# in and thus that is the default project name used by Docker compose.

set -e -u

COMPOSE_PROJECT_NAME=${COMPOSE_PROJECT_NAME:-it}
TEST_SELECTOR=${TEST_SELECTOR:-}

# assumes that scale=1 for the specified container
container_name() {
    CONTAINER_NAME="$1"
    echo "${COMPOSE_PROJECT_NAME}_${CONTAINER_NAME}_1"
}

wait_for_container_up() {
    CONTAINER_NAME="$1"
    SECONDS_TO_WAIT=${2:-15}

    UP=0
    while [ ${SECONDS_TO_WAIT} -ge 1 ]; do
        echo -n "Waiting ${SECONDS_TO_WAIT} seconds for Docker container ${CONTAINER_NAME} to be up: "
        STATE=$(docker inspect --format "{{.State.Running}}" ${CONTAINER_NAME} || true)
        echo ${STATE}
        [ "${STATE}" == "true" ] && UP=1 && break
        sleep 1s
        let "SECONDS_TO_WAIT=SECONDS_TO_WAIT-1"
    done

    if [ $UP -eq 1 ]; then
        echo "Docker container ${CONTAINER_NAME} is up"
        return 0
    else
        echo >&2 "Docker container ${CONTAINER_NAME} is still NOT Up"
        return 1
    fi
}

wait_for_port_connect() {
    FQDN="$1"
    PORT="$2"
    SECONDS_TO_WAIT=${3:-15}

    CONNECTED=0
    while [ ${SECONDS_TO_WAIT} -ge 1 ]; do
        echo "Waiting ${SECONDS_TO_WAIT} seconds to connect to ${FQDN}:${PORT}.."
        nc -z ${FQDN} ${PORT} && CONNECTED=1 && break
        sleep 1s
        let "SECONDS_TO_WAIT=SECONDS_TO_WAIT-1"
    done

    if [ $CONNECTED -eq 1 ]; then
        echo "Connected to ${FQDN}:${PORT}"
        return 0
    else
        echo >&2 "UNABLE to connect to ${FQDN}:${PORT}"
        return 1
    fi
}

sign_zone() {
    ZONE_DOMAIN="$1"
    ZONE_NSD_CONTAINER="$2"

    echo
    echo ":: Signing zone '${ZONE_DOMAIN}''.."
    wait_for_container_up ${ZONE_NSD_CONTAINER}

    SIGN_CMD="docker exec ${ZONE_NSD_CONTAINER} /opt/nsd-sign-zone.sh"

    if [ "${ZONE_DOMAIN}" == "." ]; then
        ${SIGN_CMD} . root
    else
        PARENT_NSD_CONTAINER="$3"
        PARENT_DOMAIN=$(echo ${ZONE_DOMAIN} | cut -d . -f 2-)
        ZONE_FILE=${ZONE_DOMAIN}
        PARENT_ZONE_FILE=${PARENT_DOMAIN}

        if [ "${PARENT_DOMAIN}" == "${ZONE_DOMAIN}" ]; then
            PARENT_DOMAIN=.
            PARENT_ZONE_FILE=root
        fi

        wait_for_container_up ${PARENT_NSD_CONTAINER}
        ${SIGN_CMD} \
            ${ZONE_DOMAIN} ${ZONE_FILE} \
            ${PARENT_DOMAIN} ${PARENT_ZONE_FILE} \
            ${PARENT_NSD_CONTAINER}
    fi
}

C_ROOT=$(container_name root)
C_MASTER=$(container_name master)
C_SUBMASTER=$(container_name submaster)
C_RESOLVER=$(container_name resolver)
C_APP=$(container_name app)

sign_zone test.nlnetlabs.tk $C_SUBMASTER $C_SUBMASTER
sign_zone nlnetlabs.tk $C_SUBMASTER $C_MASTER
sign_zone tk $C_MASTER $C_ROOT
sign_zone . $C_ROOT

echo
echo ':: Retrieving root trust anchor for use by the resolver..'
# Not sure why docker cp root:/tmp/zsk.key /tmp/root_zsk.key doesn't work...
docker exec $C_ROOT cat /tmp/zsk.key >/tmp/root_zsk.key

echo
echo ':: Installing root trust anchor in the resolver..'
wait_for_container_up $C_RESOLVER
docker cp /tmp/root_zsk.key $C_RESOLVER:/var/lib/unbound/my-root.key
docker exec $C_RESOLVER perl -pi -e 's|^#   auto-trust-anchor-file:.+|   auto-trust-anchor-file: "/var/lib/unbound/my-root.key"|' /etc/unbound/unbound.conf
docker exec $C_RESOLVER unbound-control reload

echo
echo ':: Verify DNS lookup from resolver -> master -> root with DNSSEC'
dig +dnssec @${RESOLVER_IP} tls1213.test.nlnetlabs.tk

echo
echo ':: Checking DNSSEC trust tree'
docker exec $C_RESOLVER drill @127.0.0.1 SOA IN -DSk /var/lib/unbound/my-root.key -r /etc/unbound/root.hints tls1213.test.nlnetlabs.tk

echo
echo ':: Installing root trust anchor in the app container..'
docker cp /tmp/root_zsk.key $C_APP:/tmp/root_zsk.key

echo
echo ':: Identifying target Docker containers'
TARGET_CONTAINERS="$(docker network inspect --format '{{range .Containers}}{{println .Name}}{{end}}' it_test_net | fgrep target | paste -sd ' ' -)"

echo
echo ':: Waiting for target Docker containers to be up..'
for C in $TARGET_CONTAINERS; do
    wait_for_container_up $C
done

echo
echo ':: Identifying target FQDNs to verify'
PROTOCOLS="ssl2 ssl3 tls1 tls1_1 tls1_2 tls1_3"
TARGETS="$(docker exec $C_SUBMASTER ldns-read-zone -E A -z /etc/nsd/test.nlnetlabs.tk | awk '{print $1}' | sed -e 's/\.$//')"

echo
echo ':: Dumping target domain TLS cert to hostname mappings'
set -o pipefail
for FQDN in ${TARGETS}; do
    echo -n -e "${FQDN}:\t"
    CERT=
    for PROT in ${PROTOCOLS}; do
        OPENSSL=/opt/openssl-old/bin/openssl
        SERVERNAME="-servername ${FQDN}"
        [[ $PROT == "tls1_3" ]] && OPENSSL=openssl
        [[ $PROT == "ssl2" ]] && SERVERNAME=
        CERT=$(echo | ${OPENSSL} s_client \
            -${PROT} \
            -showcerts \
            ${SERVERNAME} \
            -connect ${FQDN}:443 \
            2>&1 \
            | grep -E '^subject=.+' \
            | grep -Eo "CN.+" \
            | cut -d '=' -f 2 \
            || echo)
        [ -n "${CERT}" ] && break
    done
    if [ -n "${CERT}" ]; then echo ${CERT}; else echo ERROR; fi
done | column -t
set +o pipefail

echo
echo ':: Dumping target domain TLS version support'
for FQDN in ${TARGETS}; do
    echo -n -e "${FQDN}:\t"
    for PROT in ${PROTOCOLS}; do
        echo -n "${PROT}: "
        SUPPORTED='-'
        OPENSSL=/opt/openssl-old/bin/openssl
        SERVERNAME="-servername ${FQDN}"
        [[ $PROT == "tls1_3" ]] && OPENSSL=openssl
        [[ $PROT == "ssl2" ]] && SERVERNAME=
        echo | ${OPENSSL} s_client -${PROT} ${SERVERNAME} -connect ${FQDN}:443 &>/dev/null && SUPPORTED='YES'
        echo -n -e "${SUPPORTED}\t"
    done
    echo
done | column -t

echo
echo ':: Waiting for Internet.nl app to become available..'
wait_for_container_up $C_APP
wait_for_port_connect app 8080 60

# TODO: sleeps are brittle, replace this with a deterministic check
echo
echo ':: Wait 15 seconds to give the app time to settle, e.g. Celery worker startup etc..'
sleep 15s

NUM_SIMULTANEOUS_TESTS=${NUM_BROWSER_NODES}
PYTEST_XDIST_ARGS="-n ${NUM_SIMULTANEOUS_TESTS}"
PYTEST_PROGRESS_ARGS="" #"--show-progress"
PYTEST_SELENIUM_ARGS="--driver Remote --host selenium --port 4444 --capability browserName firefox"
PYTEST_HTML_ARGS="--html=/tmp/it-report/$(date +'%Y%m%d_%H%M%S').html"
PYTEST_ARGS="-vv" # to get the full diff in case of failed assertions

if [ "${TEST_SELECTOR}" != "" ]; then
    PYTEST_ARGS="${PYTEST_ARGS} -k ${TEST_SELECTOR}"
fi

echo
echo ":: Execute the browser based integration test suite.. (TEST_SELECTOR: ${TEST_SELECTOR})"

docker exec $C_APP sudo mkdir -p /tmp/it-report/coverage-data
docker exec $C_APP sudo chmod -R a+w /tmp/it-report
docker exec $C_APP pytest \
    ${PYTEST_ARGS} \
    ${PYTEST_XDIST_ARGS} \
    ${PYTEST_PROGRESS_ARGS} \
    ${PYTEST_HTML_ARGS} \
    ${PYTEST_SELENIUM_ARGS} || true

docker exec $C_APP /opt/coverage-finalize.sh