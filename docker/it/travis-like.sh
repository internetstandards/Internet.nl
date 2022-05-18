#!/bin/bash
set -e -u -x

echo
echo before_install
echo
docker --version
docker-compose --version
docker-compose kill
docker-compose down -v --remove-orphans
# docker-compose build --parallel would be nice but doesn't seem to always
# build correctly, thus we are forced to use the slow serial build instead:
docker-compose build
docker-compose up --force-recreate --no-start

echo
echo script
echo
docker-compose up --no-recreate --no-build --abort-on-container-exit --exit-code-from testrunner --no-color | grep -E '^testrunner'

echo
echo after_script
echo
docker-compose ps >/tmp/docker-compose.log
docker-compose logs -t --no-color >>/tmp/docker-compose.log
docker-compose kill
docker-compose down -v
