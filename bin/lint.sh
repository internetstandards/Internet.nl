#!/usr/bin/env bash

set -x

# runs linting commands

fail=0

if ! pylama --skip "**/migrations/*" ${@}; then
    echo -e "\e[31mSome pylama checks failed.\e[0m"
    fail=1
fi
if ! black --line-length 120 --check ${@}; then
    echo -e "\e[31mSome files are not formatted correctly. Run \`make fix\` to fix.\e[0m"
    fail=1
fi
if ! shellcheck -e SC1071 docker/cron/periodic/*/*; then
    echo -e "\e[31mSome shell scripts have issues.\e[0m"
    fail=1
fi

if ! SKIP_SECRET_KEY_CHECK=True CACHE_LOCATION= ENABLE_BATCH= DJANGO_DATABASE=dev ./manage.py makemigrations --noinput --check --dry-run; then
    echo -e "\e[31mNot all migrations have been created after changes to \`models.py\`. Run \`make makemigrations\` to update migrations.\e[0m"
    fail=1
fi

exit "$fail"
