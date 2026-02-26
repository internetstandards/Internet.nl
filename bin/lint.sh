#!/usr/bin/env bash

set -x

# runs linting commands

fail=0

# E203: black uses [1 : 2] style which conflicts with pycodestyle
# E252: missing whitespace around parameter default (black handles formatting)
# W605: invalid escape sequence (false positives in some string patterns)
if ! flake8 --max-line-length=120 --exclude="*/migrations/*" --extend-ignore="E203,E252,W605" "${@}"; then
    echo -e "\e[31mSome flake8 checks failed.\e[0m"
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
