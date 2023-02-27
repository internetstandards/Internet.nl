#!/bin/bash

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

REDIS_CONS=$(netstat -antlp | grep :6379 | grep "CLOSE_WAIT" | wc -l)

if [ ${REDIS_CONS} -gt 50000 ]; then
    logger --tag redis-connections-limit-cron "Redis is having too much connections in CLOSED state. Restarting internetnl batch services"
    for i in $(ls -1 /etc/systemd/system/internetnl-batch*.service); do /bin/systemctl restart `basename $i`; done
fi
