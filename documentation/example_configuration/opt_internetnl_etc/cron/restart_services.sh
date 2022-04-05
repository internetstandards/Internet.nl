#!/bin/bash

for i in $(ls -1 /etc/systemd/system/internetnl-single*.service); do systemctl restart `basename $i`; done >> /opt/internetnl/log/cron_restart_services.log

