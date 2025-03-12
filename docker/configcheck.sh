#!/usr/bin/env sh

set -e

# if routinator service is disabled, the ROUTINATOR_URL variable should be set to a valid url
if [[ $COMPOSE_PROFILES != *"routinator"* ]] and [[ -z $ROUTINATOR_URL ]]; then
    echo "Error: routinator service is disabled, but ROUTINATOR_URL is not set."
    echo "Please set ROUTINATOR_URL to a valid routinator service url or add the 'routinator' to COMPOSE_PROFILES in `docker/local.env`."
    exit 1
fi

if [[ $COMPOSE_PROFILES != *"routinator"* ]] and [[ $ROUTINATOR_URL == "http://routinator:9556/api/v1/validity" ]]; then
    echo "Error: routinator service is disabled, but ROUTINATOR_URL is set to use internal routinator service."
    echo "Please set ROUTINATOR_URL to a valid routinator service url or add the 'routinator' to COMPOSE_PROFILES in `docker/local.env`."
    exit 1
fi

if [[ $COMPOSE_PROFILES == *"alertmanager"* ]] and [[ $COMPOSE_PROFILES != *"monitoring"* ]]; then
    echo "Error: alertmanager service is enabled, but monitoring service is disabled."
    echo "Please add the 'monitoring' to COMPOSE_PROFILES or remove the 'alertmanager' from COMPOSE_PROFILES in `docker/local.env`."
    exit 1
fi
