#!/bin/bash
set -e -u -x

echo
echo before_install
echo
docker --version
docker-compose --version
docker-compose kill
docker-compose down -v --remove-orphans
docker-compose build
docker-compose create --force-recreate

echo
echo script
echo
docker-compose up --no-recreate --no-build --abort-on-container-exit --exit-code-from testrunner --no-color | grep -E '^(testrunner|app)'

echo
echo after_script
echo
docker-compose ps >/tmp/docker-compose.log
docker-compose logs -t --no-color >>/tmp/docker-compose.log
docker-compose kill
docker-compose down -v
