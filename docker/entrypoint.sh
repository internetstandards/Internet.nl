#!/bin/bash
# This script is installed in the Docker "app" image and is executed when a container is started from the image.
set -exvu

APP_PATH=/app

# Some env stuff needed in this script...
RUN_SERVER_CMD=${RUN_SERVER_CMD:-runserver}
LDNS_DANE_VALIDATION_DOMAIN=${LDNS_DANE_VALIDATION_DOMAIN:-internet.nl}

# Start Unbound and ensure it is the default resolver. LDNS-DANE uses this.
sudo unbound-control start
sudo unbound-control status

# Sanity check our DNS configuration. The default resolver should be DNSSEC
# capable. If not LDNS-DANE will fail to verify domains. Internet.NL calls out
# to LDNS-DANE so this needs to work for Internet.NL tests to work properly.
ldns-dane -n -T verify ${LDNS_DANE_VALIDATION_DOMAIN} 443 || echo >&2 "ERROR: Please run this container with --dns 127.0.0.1"

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
../manage.py compilemessages

cd ${APP_PATH}
# Check for database connectivity
docker/postgres-ping.sh postgresql://${POSTGRES_USER}@${POSTGRES_HOST}/${POSTGRES_DB}

# Prepare the database for use
./manage.py migrate

# Optional steps for the batch dev environment
if [ ${ENABLE_BATCH} == "True" ]; then
    # create indexes
    ./manage.py api_create_db_indexes
    # guarantee the existence of a test_user in the db
    ./manage.py api_users register -u test_user -n test_user -o test_user -e test_user || :
    # generate API documentation
    cp ${APP_PATH}/internetnl/batch_api_doc_conf{_dist,}.py
    ln -sf ${APP_PATH}/checks/static ${APP_PATH}/static # static/ is not served, checks/static is
    ./manage.py api_generate_doc # creates openapi.yaml in static/
fi

# Start Celery
if [ ${ENABLE_BATCH} == "True" ]; then
    celery -A internetnl multi start \
	worker db_worker slow_db_worker \
    batch_scheduler batch_main batch_callback batch_slow \
	-c:1 5 -Q:1 celery -c:2 1 -Q:2 db_worker -c:3 3 -Q:3 slow_db_worker \
    -c:4 1 -Q batch_scheduler -c:5 5 -Q:5 batch_main -c:6 1 -Q:6 batch_callback -c:7 1 -Q:7 batch_slow \
        -l info --without-gossip --time-limit=300 --pidfile='/app/%n.pid' \
        --logfile='/app/%n%I.log' -P eventlet &
else
    celery -A internetnl multi start \
        worker db_worker slow_db_worker \
        -c:1 5 -c:2 1 -Q:2 db_worker -c:3 3 -Q:3 slow_db_worker \
        -l info --without-gossip --time-limit=300 --pidfile='/app/%n.pid' \
        --logfile='/app/%n%I.log' -P eventlet &
fi

# Start Celery Beat
celery -A internetnl beat &

# Wait a little while for all 3 Celery worker groups to become ready
if [ ${ENABLE_BATCH} == "True" ]; then
    docker/celery-ping.sh 7 20
else
    docker/celery-ping.sh 3
fi

# Tail the Celery log files so that they appear in Docker logs output
tail -F -n 1000 *.log &

# Start the Django web server
./manage.py ${RUN_SERVER_CMD} 0.0.0.0:8080
