#!/bin/bash

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

REDIS_CONS=$(netstat -antlp | grep :6379 | grep "CLOSE_WAIT" | wc -l)

if [ ${REDIS_CONS} -gt 60000 ]; then
	logger --tag redis-connections-limit-cron "Redis is having too much connections in CLOSE_WAIT state. Restarting internetnl batch services and redis."
	for i in $(ls -1 /etc/systemd/system/internetnl-batch*.service); do /bin/systemctl restart `basename $i`; done
	/bin/systemctl restart redis-server
fi

