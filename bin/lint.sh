#!/usr/bin/env bash

set -x

# runs linting commands

fail=0

pylama --skip "**/migrations/*" ${@} || fail=1
black --line-length 120 --check ${@} || fail=1
shellcheck -e SC1071 docker/cron/periodic/*/* || fail=1

SKIP_SECRET_KEY_CHECK=True CACHE_LOCATION= ENABLE_BATCH= ./manage.py makemigrations --noinput --check --dry-run || fail=1

exit "$fail"
