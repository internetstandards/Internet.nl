#!/bin/bash
# This script is installed in the Docker "app" image and is executed when a container is started from the image.
# todo: could add env to the path, activate doesn't seem to function? Also add unbound to the path.
set -exvu

ADMIN_EMAIL=${ADMIN_EMAIL:-admin@i.dont.exist}
CACHE_TTL=${CACHE_TTL:-200}
ENABLE_BATCH=${ENABLE_BATCH:-False}
POSTGRES_HOST=${POSTGRES_HOST:-localhost}
POSTGRES_USER=${POSTGRES_USER:-internetnl}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD:-password}
POSTGRES_DB=${POSTGRES_DB:-internetnl_db1}
RABBITMQ_HOST=${RABBITMQ_HOST:-localhost}
REDIS_HOST=${REDIS_HOST:-localhost}
ROUTINATOR_HOST=${ROUTINATOR_URL:-localhost:9556}
RUN_SERVER_CMD=${RUN_SERVER_CMD:-runserver}
LDNS_DANE_VALIDATION_DOMAIN=${LDNS_DANE_VALIDATION_DOMAIN:-internet.nl}

# Start Unbound and ensure it is the default resolver. LDNS-DANE uses this.
sudo /opt/unbound2/sbin/unbound-control start
sudo /opt/unbound2/sbin/unbound-control status

# Sanity check our DNS configuration. The default resolver should be DNSSEC
# capable. If not LDNS-DANE will fail to verify domains. Internet.NL calls out
# to LDNS-DANE so this needs to work for Internet.NL tests to work properly.
ldns-dane -n -T verify ${LDNS_DANE_VALIDATION_DOMAIN} 443 || echo >&2 "ERROR: Please run this container with --dns 127.0.0.1"

# Configure the Internet.nl Django app, e.g. to know how to connect to RabbitMQ, Redis and PostgreSQL.
# Default values for the environment variables referred to below are provided by the Docker image but can be
# overridden at container creation time.
sed \
    -e "s|DEBUG = False|DEBUG = True|g" \
    -e "s|ENABLE_BATCH = False|ENABLE_BATCH = ${ENABLE_BATCH}|g" \
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
    -e "s|ROUTINATOR_URL = 'http://localhost:9556/api/v1/validity'|ROUTINATOR_URL = 'http://${ROUTINATOR_HOST}/api/v1/validity'|g" \
    ${APP_PATH}/internetnl/settings.py-dist > ${APP_PATH}/internetnl/settings.py

# configure Django logging
cat << EOF >> ${APP_PATH}/internetnl/settings.py
if DEBUG:
    LOGGING = {
        'version': 1,
        'disable_existing_loggers': False,
        'handlers': {
            'file': {
                'level': 'INFO',
                'class': 'logging.FileHandler',
                'filename': 'django.log',
            },
        },
        'loggers': {
            'django': {
                'handlers': ['file'],
                'level': 'INFO',
                'propagate': True,
            },
        },
    }
EOF

# Prepare translations for use
cd ${APP_PATH}/checks
.venv/bin/python ./manage.py compilemessages

cd ${APP_PATH}
# Check for database connectivity
docker/postgres-ping.sh postgresql://${DB_USER}@${DB_HOST}:${DB_PORT}/${DB_NAME}

# Prepare the database for use
.venv/bin/python ./manage.py migrate

# Optional steps for the batch dev environment
if [ ${ENABLE_BATCH} == "True" ]; then
    # create indexes
    .venv/bin/python ./manage.py api_create_db_indexes
    # guarantee the existence of a test_user in the db
    .venv/bin/python ./manage.py api_users register -u test_user -n test_user -o test_user -e test_user || :
    # generate API documentation
    cp ${APP_PATH}/internetnl/batch_api_doc_conf{_dist,}.py
    ln -sf ${APP_PATH}/checks/static ${APP_PATH}/static # static/ is not served, checks/static is
    .venv/bin/python ./manage.py api_generate_doc # creates openapi.yaml in static/
fi

# Start Celery
# Todo: should this just start the celery workers via systemd while we're at it?
# queues/settings taken from the shipped config file
if [ ${ENABLE_BATCH} == "True" ]; then
    .venv/bin/celery -A internetnl multi start \
	db_worker slow_db_worker worker_slow batch_slow batch_main batch_callback celery default nassl_worker ipv6_worker mail_worker web_worker resolv_worker dnssec_worker \
	-c 1 -c:1-6 1 -Q:1 db_worker -Q:2 slow_db_worker -Q:3 worker_slow -Q:4 batch_slow -Q:5 celery -Q:6 default -c:7 50 -Q:7 batch_main -c:8 2 -Q:8 batch_callback -c:9 150 -Q:9 nassl_worker -c:10 20 -Q:10 ipv6_worker -c:11 20 -Q:11 mail_worker -c:12 20 -Q:12 web_worker -c:13 50 -Q:13 resolv_worker -c:14 20 -Q:14 dnssec_worker \
        -l info --without-gossip --time-limit=300 --pidfile='/app/%n.pid' \
        --logfile='/app/%n%I.log' -P eventlet &
else
    .venv/bin/celery -A internetnl multi start \
        worker db_worker slow_db_worker nassl_worker ipv6_worker mail_worker web_worker resolv_worker dnssec_worker \
        -c:1 10 -c:2 3 -Q:2 db_worker -c:3 3 -Q:3 slow_db_worker -c:4 150 -Q:4 nassl_worker -c:5 20 -Q:5 ipv6_worker -c:6 20 -Q:6 mail_worker -c:7 20 -Q:7 web_worker -c:8 50 -Q:8 resolv_worker -c:9 20 -Q:9 dnssec_worker \
        -l info --without-gossip --time-limit=300 --pidfile='/app/%n.pid' \
        --logfile='/app/%n%I.log' -P eventlet &
fi

# Start Celery Beat
.venv/bin/celery -A internetnl beat &

# Wait a little while for all 3 Celery worker groups to become ready
if [ ${ENABLE_BATCH} == "True" ]; then
    docker/celery-ping.sh 7 20
else
    docker/celery-ping.sh 3
fi

# Tail the Celery log files so that they appear in Docker logs output
tail -F -n 1000 *.log &

# Start the Django web server
.venv/bin/python ./manage.py ${RUN_SERVER_CMD} 0.0.0.0:8080
