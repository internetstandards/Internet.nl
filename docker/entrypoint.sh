#!/bin/bash
# This script is installed in the Docker "app" image and is executed when a container is started from the image.
set -exvu

ADMIN_EMAIL=${ADMIN_EMAIL:-admin@i.dont.exist}
CACHE_TTL=${CACHE_TTL:-200}
POSTGRES_HOST=${POSTGRES_HOST:-localhost}
POSTGRES_USER=${POSTGRES_USER:-internetnl}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD:-password}
POSTGRES_DB=${POSTGRES_DB:-internetnl_db1}
RABBITMQ_HOST=${RABBITMQ_HOST:-localhost}
REDIS_HOST=${REDIS_HOST:-localhost}
RUN_SERVER_CMD=${RUN_SERVER_CMD:-runserver}
LDNS_DANE_VALIDATION_DOMAIN=${LDNS_DANE_VALIDATION_DOMAIN:-internet.nl}

APP_PATH=/app

# Start Unbound and ensure it is the default resolver. LDNS-DANE uses this.
sudo unbound-control start
sudo unbound-control status

# Sanity check our DNS configuration. The default resolver should be DNSSEC
# capable. If not LDNS-DANE will fail to verify domains. Internet.NL calls out
# to LDNS-DANE so this needs to work for Internet.NL tests to work properly.
ldns-dane -n -T verify ${LDNS_DANE_VALIDATION_DOMAIN} 443 || echo >&2 "ERROR: Please run this container with --dns 127.0.0.1"

# Configure the Internet.nl Django app, e.g. to know how to connect to RabbitMQ, Redis and PostgreSQL.
# Default values for the environment variables referred to below are provided by the Docker image but can be
# overridden at container creation time.
sed \
    -e "s|DEBUG = False|DEBUG = True|g" \
    -e "s|localhost:15672|${RABBITMQ_HOST}:15672|g" \
    -e "s|localhost:6379|${REDIS_HOST}:6379|g" \
    -e "s|BROKER_URL = 'amqp://guest@localhost//'|BROKER_URL = 'amqp://guest@${RABBITMQ_HOST}//'|g" \
    -e "s|ALLOWED_HOSTS = .*|ALLOWED_HOSTS = [\"*\"]|g" \
    -e "s|django@internet.nl|"${ADMIN_EMAIL}"|g" \
    -e "s|'HOST': '127.0.0.1'|'HOST': '${POSTGRES_HOST}'|g" \
    -e "s|'NAME': '<db_name>'|'NAME': '${POSTGRES_DB}'|g" \
    -e "s|'USER': '<db_user>'|'USER': '${POSTGRES_USER}'|g" \
    -e "s|'PASSWORD': 'password'|'PASSWORD': '${POSTGRES_PASSWORD}'|g" \
    -e "s|CACHE_TTL = .*|CACHE_TTL = ${CACHE_TTL}|g" \
    ${APP_PATH}/internetnl/settings.py-dist > ${APP_PATH}/internetnl/settings.py

# Prepare translations for use
cd ${APP_PATH}/checks
../manage.py compilemessages

# Prepare the database for use
cd ${APP_PATH}
./manage.py migrate checks

# Start Celery
celery -A internetnl multi start \
    worker db_worker slow_db_worker \
    -c:1 5 -c:2 1 -Q:2 db_worker -c:3 3 -Q:3 slow_db_worker \
    -l info --without-gossip --time-limit=300 -P eventlet &

# Start Celery Beat
celery -A internetnl beat &

# Wait a little while for all 3 Celery worker groups to become ready
docker/celery-ping.sh 3

# Tail the Celery log files so that they appear in Docker logs output
tail -F -n 1000 *.log &

# Start the Django web server
./manage.py ${RUN_SERVER_CMD} 0.0.0.0:8080