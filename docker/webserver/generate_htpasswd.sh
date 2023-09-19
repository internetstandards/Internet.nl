# generate htaccess files from environment variables. Add a user:password for every comma separated pair
echo $BATCH_AUTH|tr ',' '\n'|tr ':' ' '| xargs --max-args=2 --no-run-if-empty htpasswd -b /etc/nginx/htpasswd/batch_api.htpasswd
echo $MONITORING_AUTH|tr ',' '\n'|tr ':' ' '| xargs --max-args=2 --no-run-if-empty htpasswd -b /etc/nginx/htpasswd/monitoring.htpasswd
echo $BASIC_AUTH|tr ',' '\n'|tr ':' ' '| xargs --max-args=2 --no-run-if-empty htpasswd -b /etc/nginx/htpasswd/basic_auth.htpasswd

# append raw entries to htpasswd file
echo $BATCH_AUTH_RAW|tr ',' '\n' >> /etc/nginx/htpasswd/batch_api.htpasswd
echo $MONITORING_AUTH_RAW|tr ',' '\n' >> /etc/nginx/htpasswd/monitoring.htpasswd
echo $BASIC_AUTH_RAW|tr ',' '\n' >> /etc/nginx/htpasswd/basic_auth.htpasswd
