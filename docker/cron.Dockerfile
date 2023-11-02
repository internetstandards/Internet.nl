FROM alpine:3.18

RUN apk add --no-cache curl

COPY docker/cron/periodic /etc/periodic/

CMD crond -f -d7