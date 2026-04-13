#!/usr/bin/env sh

# Small wrapper around user mgmt script shipped in webserver image
# For both convenience, and to have a suitable command to put in sudo

set -e # fail on error

# determine install base (parent of directory containing this file)
INTERNETNL_INSTALL_BASE=$(dirname "$(dirname "$(readlink -f "$0")")")

"$INTERNETNL_INSTALL_BASE/docker/compose.sh" exec -ti webserver /user_manage_inner.sh "$1" "$2"
