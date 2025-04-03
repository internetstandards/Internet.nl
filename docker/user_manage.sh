#!/usr/bin/env sh
# Small wrapper around user mgmt script shipped in webserver image
# For both convenience, and to have a suitable command to put in sudo
/usr/bin/docker compose --env-file=docker/defaults.env --env-file=docker/host.env --env-file=docker/local.env exec -ti webserver /user_manage_inner.sh "$1" "$2"
