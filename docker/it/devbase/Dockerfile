FROM ubuntu:19.04

ENV DEBIAN_FRONTEND noninteractive

# install helper packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    bsdmainutils \
    dnsutils \
    docker.io \
    inetutils-ping \
    ldnsutils \
    less \
    lsof \
    netcat \
    net-tools \
    psmisc \
    python-pip \
    rename \
    vim
RUN pip install setuptools j2cli

# install helper scripts
COPY *.sh /opt/
RUN chmod +x /opt/*.sh