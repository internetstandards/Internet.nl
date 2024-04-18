#!/bin/sh
echo $MONITORING_AUTH_RAW|tr ',' '\n' >> /etc/nginx/htpasswd/monitoring.htpasswd

# enable basic auth when user/password is configured
touch /etc/nginx/conf.d/basic_auth.include
if [ "$AUTH_ALL_URLS" != "False" ] || [ "$ENABLE_BATCH" != "False" ]; then
  echo 'auth_basic "Please enter your access username and password";auth_basic_user_file /etc/nginx/htpasswd/external/users.htpasswd;' > /etc/nginx/conf.d/basic_auth.include
fi

# create IP allow list
if [ ! "$ALLOW_LIST" = "" ];then
  echo "satisfy any;" > /etc/nginx/conf.d/allow_list.conf
  IFS=","
  for ip in $ALLOW_LIST;do
    echo "allow $ip;" >> /etc/nginx/conf.d/allow_list.conf
  done
  echo "deny all;" >> /etc/nginx/conf.d/allow_list.conf
fi

# verify that when debug is enabled, authentication is also enabled
if [ ! "$DEBUG" = "False" ] && [ "$AUTH_ALL_URLS$ALLOW_LIST" = "" ];then
  printf "\nMust have AUTH_ALL_URLS or ALLOW_LIST authentication configured if DEBUG is not 'False'!\n"
  exit 1
fi
