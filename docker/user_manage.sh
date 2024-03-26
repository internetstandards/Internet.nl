#!/usr/bin/env sh
# Small wrapper around user mgmt script shipped in webserver image
# For both convenience, and to have a suitable command to put in sudo
/usr/bin/docker compose --env-file=/opt/Internet.nl/docker/defaults.env --env-file=/opt/Internet.nl/docker/host.env --env-file=/opt/Internet.nl/docker/local.env exec -ti webserver /user_manage_inner.sh "$1" "$2"
