#!/usr/bin/env sh

set -e

cd /opt/Internet.nl/

echo "Updating to release: $RELEASE"

curl --silent --show-error --fail --remote-name --location --max-redirs 0 --output-dir docker \
  "https://raw.githubusercontent.com/internetstandards/Internet.nl/${RELEASE}/docker/defaults.env"
curl --silent --show-error --fail --remote-name --location --max-redirs 0 --output-dir docker \
  "https://raw.githubusercontent.com/internetstandards/Internet.nl/${RELEASE}/docker/docker-compose.yml"
env -i RELEASE="$RELEASE" docker compose --env-file=docker/defaults.env --env-file=docker/host.env --env-file=docker/local.env pull
env -i RELEASE="$RELEASE" docker compose --env-file=docker/defaults.env --env-file=docker/host.env --env-file=docker/local.env up --remove-orphans --wait --no-build

echo "RELEASE=$RELEASE # auto-update: '$AUTO_UPDATE_BRANCH' $(date)" >> docker/local.env

echo "Update completed"