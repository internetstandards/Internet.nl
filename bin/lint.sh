#!/usr/bin/env bash

set -x

# runs linting commands

fail=0

pylama --skip "**/migrations/*" ${@} || fail=1
black --line-length 120 --check ${@} || fail=1
shellcheck -e SC1071 docker/cron/periodic/*/* || fail=1

if ! SKIP_SECRET_KEY_CHECK=True CACHE_LOCATION= ENABLE_BATCH= DJANGO_DATABASE=dev ./manage.py makemigrations --noinput --check --dry-run; then
    echo -e "\e[31mNot all migrations have been created after changes to \`models.py\`. Run \`make makemigrations\` to update migrations.\e[0m"
    fail=1
fi

exit "$fail"
