FROM alpine:3.18

RUN apk add --no-cache curl postgresql15 python3 py3-prometheus-client py3-requests pigz

COPY docker/cron/periodic /etc/periodic/

CMD crond -f -d7
