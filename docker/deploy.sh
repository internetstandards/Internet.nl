#!/usr/bin/env sh

set -e

cd /opt/Internet.nl/

echo "Deploying release: $RELEASE"

# copy release specific support files
cp -v /dist/docker/* docker

# set release version in local.env config
echo "RELEASE='$RELEASE' # deploy $(date)" >> docker/local.env

# download release images
docker compose --env-file=docker/defaults.env --env-file=docker/host.env --env-file=docker/local.env pull

# bring up application with new release
docker compose --env-file=docker/defaults.env --env-file=docker/host.env --env-file=docker/local.env up --remove-orphans --wait --no-build

echo "Deploy completed"
