FROM alpine:3.18

RUN apk add --no-cache curl postgresql15

COPY docker/cron/periodic /etc/periodic/

CMD crond -f -d7