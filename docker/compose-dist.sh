#!/usr/bin/env sh

# wrapper to run the right compose command with the right environment variables from the util container

set -e

# determine install base for multi environment deployments (parent of directory containing this file)
INTERNETNL_INSTALL_BASE=$(dirname "$(dirname "$(readlink -f "$0")")")

exec docker run -ti --rm --pull=never \
  --volume /var/run/docker.sock:/var/run/docker.sock \
  --volume "$INTERNETNL_INSTALL_BASE:/opt/Internet.nl" \
  --workdir /opt/Internet.nl \
  --network none \
  "ghcr.io/internetstandards/util:$RELEASE" \
  docker compose --env-file=docker/defaults.env --env-file=docker/host.env --env-file=docker/local.env "$@"
