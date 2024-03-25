#!/bin/sh
if [ "$ENABLE_BATCH" = True ] && [ "$BASIC_AUTH_RAW$ALLOW_LIST" != "" ]; then
  echo "ENABLE_BATCH must not be combined with BASIC_AUTH_RAW or ALLOW_LIST"
fi

# enable basic auth when user/password is configured
if [ ! "$BASIC_AUTH_RAW" = "" ];then
  echo 'auth_basic "Please enter your basic access username and password";auth_basic_user_file /etc/nginx/htpasswd/basic_auth.htpasswd;' > /etc/nginx/conf.d/basic_auth.conf
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
if [ ! "$DEBUG" = "False" ] && [ "$BASIC_AUTH_RAW$ALLOW_LIST" = "" ];then
  printf "\nMust have BASIC_AUTH_RAW or ALLOW_LIST authentication configured if DEBUG is not 'False'!\n"
  exit 1
fi
