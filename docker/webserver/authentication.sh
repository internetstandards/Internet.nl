#!/bin/sh

# This script writes to /etc/nginx/conf.d/ to supplement the nginx config
# *.conf files are auto included in the config
# *.include files only where specified

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

NGINX_INCLUDE_BATCH_AUTH=$(cat << 'EOF'
    auth_basic "Please enter your batch username and password";
    auth_basic_user_file /etc/nginx/htpasswd/external/batch_api.htpasswd;
    # pass logged in user to Django
    proxy_set_header REMOTE-USER $remote_user;
EOF
)

if [ "$ENABLE_BATCH" = True ] && [ "$DISABLE_GLOBAL_BATCH_AUTH" != True ]; then
    echo "$NGINX_INCLUDE_BATCH_AUTH" > /etc/nginx/conf.d/batch_auth_global.include
else
    echo > /etc/nginx/conf.d/batch_auth_global.include
fi
echo "$NGINX_INCLUDE_BATCH_AUTH" > /etc/nginx/conf.d/batch_auth_always.include
