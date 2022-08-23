#!/bin/bash
# Copyright: 2022, ECP, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0

set -eu

if [[ $# -gt 3 || "$1" == "--help" || "$1" == "-h" ]]; then
    echo >&2 "Usage: $(basename $0) [<pg connection string> [<num retries=10> [<connection timeout (int seconds)=1>"
    echo >&2 "Exits with code 0 if Postgres db is reachable, 1 otherwise."
    exit 1
fi

CONN_STRING=${1:-postgresql://internetnl@localhost/internetnl_db1}
MAX_RETRIES=${2:-10}
TIMEOUT=${3:-1}

TRY_COUNT=0
while [ ${TRY_COUNT} -le ${MAX_RETRIES} ]; do
    echo -n "Trying Postgresql server [${TRY_COUNT}/${MAX_RETRIES}]: .. "
    pg_isready -d ${CONN_STRING} -t ${TIMEOUT} 2>/dev/null
    [ $? -eq 0 ] && break
    let "TRY_COUNT=TRY_COUNT+1"
done

test ${TRY_COUNT} -le ${MAX_RETRIES}
