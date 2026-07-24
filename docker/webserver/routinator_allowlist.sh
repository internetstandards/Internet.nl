#!/bin/sh

set -x -o pipefail

# create IP allow list
if [ ! "$ROUTINATOR_ALLOW_LIST" = "" ];then
  IFS=","
  for ip in $ROUTINATOR_ALLOW_LIST;do
    echo "allow $ip;" >> /etc/nginx/conf.d/routinator_allow_list.include
  done
else
  # create empty file if there is no allowlist so the include doesn't break
  touch /etc/nginx/conf.d/routinator_allow_list.include
fi
