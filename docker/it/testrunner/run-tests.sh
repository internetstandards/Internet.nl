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
TEST_MAX_FAIL=${TEST_MAX_FAIL:-}

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
        echo -n "Waiting ${SECONDS_TO_WAIT} seconds for Docker container ${CONTAINER_NAME} to be up:"
        STATE=$(docker inspect --format "{{.State.Running}}" ${CONTAINER_NAME} || true)
        echo -n " ${STATE}"
        [ "${STATE}" == "true" ] && UP=1 && break
        sleep 1s
        let "SECONDS_TO_WAIT=SECONDS_TO_WAIT-1"
    done

    if [ $UP -eq 1 ]; then
        echo
        return 0
    else
        echo >&2 "Docker container ${CONTAINER_NAME} is still NOT Up"
        return 1
    fi
}

wait_for_http_connect() {
    FROM_CONTAINER="$1"
    FQDN="$2"
    PORT="$3"
    SECONDS_TO_WAIT=${4:-15}

    CONNECTED=0
    while [ ${SECONDS_TO_WAIT} -ge 1 ]; do
        echo "Waiting ${SECONDS_TO_WAIT} seconds to connect from ${FROM_CONTAINER} to http://${FQDN}:${PORT}/.."
        docker exec ${FROM_CONTAINER} curl -4 -s -o/dev/null http://${FQDN}:${PORT}/ && CONNECTED=1 && break
        sleep 5s
        let "SECONDS_TO_WAIT=SECONDS_TO_WAIT-5"
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
echo ':: Interrogating test.nlnetlabs.tk target servers..'
set -o pipefail
HEADER_ROW=1
for FQDN in ${TARGETS}; do
    if [ "${HEADER_ROW}" -eq 1 ]; then
        echo -e -n "FQDN"
        for PROT in ${PROTOCOLS}; do echo -e -n "\t${PROT}"; done
        echo -e -n "\tServer\tCertificate\tBest Cipher\n"
        HEADER_ROW=0
    fi

    HOST=$(echo $FQDN | sed -e 's/\.test\.nlnetlabs\.tk//')

    HTTP_REQUEST="GET / HTTP/1.1\nConnection: close\nHost: ${FQDN}\n\n"
    SERVER_NAME="Unknown"
    CERT="Unknown"
    CIPHER="Unknown"
    echo -n -e "${HOST}:\t"
    for PROT in ${PROTOCOLS}; do
        SUPPORTED='-'
        OPENSSL=/opt/openssl-old/bin/openssl
        SERVERNAME="-servername ${FQDN}"
        [[ $PROT == "tls1_3" ]] && OPENSSL=openssl
        [[ $PROT == "ssl2" ]] && SERVERNAME=
        echo | timeout -k 1 2s ${OPENSSL} s_client -${PROT} ${SERVERNAME} -connect ${FQDN}:443 &>/dev/null && SUPPORTED='YES'
        echo -n -e "${SUPPORTED}\t"
        if [ "${SUPPORTED}" == "YES" ]; then
            [ "${SERVER_NAME}" == "Unknown" ] && SERVER_NAME=$(echo -e "${HTTP_REQUEST}" | timeout -k 1 2s ${OPENSSL} s_client -quiet -${PROT} ${SERVERNAME} -connect ${FQDN}:443 2>&1 | grep -E '^Server:' | cut -c 9- | tr -d "\r\n" || echo)
            [ "${CERT}" == "Unknown" ] && CERT=$(echo | timeout -k 1 2s ${OPENSSL} s_client -showcerts -${PROT} ${SERVERNAME} -connect ${FQDN}:443 2>&1 | grep -E '^subject=.+' | grep -Eo "CN.+" | cut -d '=' -f 2 | tr -d '[:space:]' || echo)
            [ "${CIPHER}" == "Unknown" ] && CIPHER=$(echo | timeout -k 1 2s ${OPENSSL} s_client -brief -${PROT} ${SERVERNAME} -connect ${FQDN}:443 2>&1 | grep -E '^Ciphersuite: .+' | cut -d ':' -f 2 | tr -d '[:space:]' || echo)
        fi
    done
    [ "${SERVER_NAME}" == "" ] && SERVER_NAME="Unavailable"
    [ "${CERT}" == "" ] && CERT="Unavailable"
    [ "${CIPHER}" == "" ] && CIPHER="Unavailable"
    echo -n -e "${SERVER_NAME}\t${CERT}\t${CIPHER}\n"
done | column -t -s $'\t'
set +o pipefail

echo
echo ':: Waiting for Internet.nl app to become available..'
wait_for_container_up $C_APP

host -t A nl.internetnl.test.nlnetlabs.tk
host -t AAAA nl.internetnl.test.nlnetlabs.tk

MAX_APP_STARTUP_SECS=${ENABLE_COVERAGE:+180}
MAX_APP_STARTUP_SECS=${MAX_APP_STARTUP_SECS:-30}

wait_for_http_connect $C_APP nl.internetnl.test.nlnetlabs.tk 8080 ${MAX_APP_STARTUP_SECS} || {
    echo >&2 'Unable to connect to the Internet.NL app: dumping netstat output'
    docker cp /opt/netstat.sh $C_APP:/tmp/
    docker exec $C_APP /tmp/netstat.sh
    echo >&2 'Aborting.'
    exit 2
}

NUM_SIMULTANEOUS_TESTS=${NUM_BROWSER_NODES}
PYTEST_XDIST_ARGS="-n ${NUM_SIMULTANEOUS_TESTS}"
PYTEST_PROGRESS_ARGS="" #"--show-progress"
PYTEST_SELENIUM_ARGS="--driver Remote --selenium-host selenium --selenium-port 4444 --capability browserName firefox"
PYTEST_HTML_ARGS="--html=/tmp/it-report/$(date +'%Y%m%d_%H%M%S').html"
PYTEST_ARGS="-vv" # to get the full diff in case of failed assertions
PYTEST_IGNORE_ARGS="--ignore=tests/unittests/"  # Don't try to run these in integration testing

if [ "${TEST_SELECTOR}" != "" ]; then
    PYTEST_ARGS="${PYTEST_ARGS} -k ${TEST_SELECTOR}"
fi

if [ "${TEST_MAX_FAIL}" != "" ]; then
    PYTEST_ARGS="${PYTEST_ARGS} --maxfail=${TEST_MAX_FAIL}"
fi

echo
echo ":: Launch Flower for Celery task processing insight.."
docker exec $C_APP flower -A internetnl --port=5555 &

echo
echo ":: Execute the browser based integration test suite.. (TEST_SELECTOR: ${TEST_SELECTOR}, TEST_MAX_FAIL: ${TEST_MAX_FAIL})"

docker exec $C_APP sudo mkdir -p /tmp/it-report/coverage-data
docker exec $C_APP sudo chmod -R a+w /tmp/it-report
docker exec $C_APP pytest \
    ${PYTEST_ARGS} \
    ${PYTEST_IGNORE_ARGS} \
    ${PYTEST_XDIST_ARGS} \
    ${PYTEST_PROGRESS_ARGS} \
    ${PYTEST_HTML_ARGS} \
    ${PYTEST_SELENIUM_ARGS} || true

docker exec $C_APP /opt/coverage-finalize.sh
