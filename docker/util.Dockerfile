FROM alpine:3.22

RUN apk add --no-cache curl postgresql15 python3 py3-prometheus-client py3-requests jq docker-cli docker-cli-compose pigz jq envsubst

# install cron tasks
COPY docker/cron/periodic /etc/periodic/

# add 5min to crontab
RUN echo "*/5    *       *       *       *       run-parts /etc/periodic/5min" >> /etc/crontabs/root

# create separate periodic config for cron-docker service
RUN cp -r /etc/crontabs /etc/crontabs-docker
RUN sed -i 's/periodic/periodic-docker/' /etc/crontabs-docker/root

# install cron tasks for cron-docker
COPY docker/cron-docker/periodic /etc/periodic-docker/

# install deploy script
COPY docker/deploy.sh /

# package deploy artifacts
RUN mkdir -p /dist/docker
COPY docker/defaults.env /dist/docker/
COPY docker/host-dist.env /dist/docker/
COPY docker/host-multi-dist.env /dist/docker/
COPY docker/compose.yaml /dist/docker/
COPY docker/user_manage.sh /dist/docker/
COPY docker/compose-dist.sh /dist/docker/
RUN chmod a-w /dist/docker/*

# add release as label for auto_update feature
ARG RELEASE
ENV RELEASE=$RELEASE
LABEL release=$RELEASE
