FROM alpine:3.20

RUN apk add --no-cache curl postgresql15 python3 py3-prometheus-client py3-requests jq docker-cli docker-cli-compose pigz

COPY docker/cron/periodic /etc/periodic/

COPY docker/cron/deploy.sh /deploy.sh

RUN mkdir -p /dist/docker
COPY docker/defaults.env /dist/docker/defaults.env
COPY docker/host-dist.env /dist/docker/host-dist.env
COPY docker/docker-compose.yml /dist/docker/docker-compose.yml
COPY docker/user_manage.sh /dist/docker/user_manage.sh

ARG RELEASE
ENV RELEASE=$RELEASE

# run crond in foreground and log output of crons
CMD crond -f -l2
