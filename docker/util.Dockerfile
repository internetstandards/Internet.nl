FROM alpine:3.20

RUN apk add --no-cache curl postgresql15 python3 py3-prometheus-client py3-requests jq docker-cli docker-cli-compose pigz

# install cron tasks
COPY docker/cron/periodic /etc/periodic/

# create separate periodic config for cron-docker service
RUN cp -r /etc/crontabs /etc/crontabs-docker
RUN sed -i 's/periodic/periodic-docker/' /etc/crontabs-docker/root

# install cron tasks for cron-docker
COPY docker/cron-docker/periodic /etc/periodic-docker/

# install deploy script
COPY docker/deploy.sh /deploy.sh

RUN mkdir -p /dist/docker
COPY docker/defaults.env /dist/docker/defaults.env
COPY docker/host-dist.env /dist/docker/host-dist.env
COPY docker/docker-compose.yml /dist/docker/docker-compose.yml
COPY docker/user_manage.sh /dist/docker/user_manage.sh
RUN chmod a-w /dist/docker/*

ARG RELEASE
ENV RELEASE=$RELEASE
