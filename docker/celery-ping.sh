#!/bin/bash
set -eu

if [[ $# -lt 1 || $# -gt 3 || "$1" == "--help" || "$1" == "-h" ]]; then
    echo >&2 "Usage: $(basename $0) <expected worker count> [<num retries=10> [<celery timeout (float seconds)=1>"
    echo >&2 "Exits with code 0 if all expected workers respond to ping with pong, 1 otherwise."
    exit 1
fi

EXPECTED_PONG_COUNT=$1
MAX_RETRIES=${2:-10}
TIMEOUT=${3:-1}

TRY_COUNT=0
while [ ${TRY_COUNT} -le ${MAX_RETRIES} ]; do
    echo -n "Pinging Celery workers [${TRY_COUNT}/${MAX_RETRIES}]: .. "
    PONG_COUNT=$(celery -A internetnl inspect ping -t ${TIMEOUT} -j 2>/dev/null | grep -Eo pong | wc -l)
    echo "${PONG_COUNT}/${EXPECTED_PONG_COUNT} ok"
    [ ${PONG_COUNT} -eq ${EXPECTED_PONG_COUNT} ] && break
    let "TRY_COUNT=TRY_COUNT+1"
done

test ${TRY_COUNT} -le ${MAX_RETRIES}
