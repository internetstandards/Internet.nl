# append raw entries to htpasswd file
echo $MONITORING_AUTH_RAW|tr ',' '\n' >> /etc/nginx/htpasswd/monitoring.htpasswd
echo $BASIC_AUTH_RAW|tr ',' '\n' >> /etc/nginx/htpasswd/basic_auth.htpasswd
