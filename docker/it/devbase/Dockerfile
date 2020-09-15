FROM ubuntu:19.04

ENV DEBIAN_FRONTEND noninteractive

# 19.04 is not supported anymore, use old-releases.ubuntu.com for the package maamger
RUN sed -i -re 's/([a-z]{2}\.)?archive.ubuntu.com|security.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list

# install helper packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    bsdmainutils \
    build-essential \
    curl \
    dnsutils \
    docker.io \
    inetutils-ping \
    ldnsutils \
    less \
    lsof \
    netcat \
    net-tools \
    openssl \
    psmisc \
    python-pip \
    rename \
    vim
RUN pip install setuptools j2cli

# Install OpenSSL 1.0.2e for serving SSL v2, SSL v3 and TLS 1.0
WORKDIR /tmp/build/openssl-old
RUN curl -fsSLo- 'https://github.com/openssl/openssl/archive/OpenSSL_1_0_2e.tar.gz' | tar zx --strip-components 1 && \
    ./config --prefix=/opt/openssl-old && make && make install

RUN rm -Rf /tmp/build

# install helper scripts
COPY *.sh /opt/
RUN chmod +x /opt/*.sh
