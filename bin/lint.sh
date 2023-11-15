#!/usr/bin/env bash

set -x

# runs linting commands

fail=0

pylama --skip "**/migrations/*" ${@} || fail=1
black --line-length 120 --check ${@} || fail=1
shellcheck docker/cron/periodic/*/* || fail=1

exit "$fail"