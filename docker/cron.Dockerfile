FROM alpine:3.18

RUN apk add --no-cache curl postgresql15 python3 py3-prometheus-client py3-requests jq docker-cli docker-cli-compose 

COPY docker/cron/periodic /etc/periodic/
COPY docker/cron/update.sh /update.sh

# run crond in foreground and log output of crons
CMD crond -f -l2