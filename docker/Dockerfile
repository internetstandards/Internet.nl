# Building this container:
# docker-compose build --no-cache --progress=plain
# Building will take some time, especially the libsass, unbound and nassl.
# todo: fix nassl build, has the anoying unknown argument -m64, even though the shell is not -m64...

# Choose an LTS. The version mentioned was not supported for a while (19)
# See the release schedule here: https://ubuntu.com/blog/what-is-an-ubuntu-lts-release
# So it would be either 18.04, 20.04 or 22.04
FROM ubuntu:20.04

LABEL vendor="Internet Standards" \
      license="Apache License, Version 2.0"

ARG BRANCH
ENV APP_PATH /app
ENV DEBIAN_FRONTEND noninteractive
ENV BRANCH ${BRANCH:-master}

# Configure the Internet.nl Django app, e.g. to know how to connect to RabbitMQ, Redis and PostgreSQL.
# Default values for the environment variables referred to below are provided by the Docker image but can be
# overridden at container start time.

# The ENV variables are also available inside the container _and_ can be changed on startup of the container.
# @see: https://stackoverflow.com/questions/39597925/how-do-i-set-environment-variables-during-the-build-in-docker
# More details about specific settings in the shipped settings-dist.py file.
# Cannot use the shipped environemnt file as the syntax is different and the values are specific.
ENV LDNS_DANE /usr/bin/ldns-dane
ENV TIME_ZONE UTC
ENV ADMIN_EMAIL admin@i.dont.exist
ENV ENABLE_BATCH False
ENV DB_NAME internetnl_db1
ENV DB_USER internetnl
ENV DB_PASSWORD password
ENV DB_HOST localhost
ENV DB_PORT 5432
ENV RABBIT_HOST localhost:15672
ENV CELERY_BROKER_URL amqp://guest@localhost//
ENV CELERY_RESULT_BACKEND redis://localhost:6379/0
ENV CACHE_LOCATION redis://localhost:6379/0

# Stuff not in the settings.py file, but in the entrypoint of the container (entrypoint.sh)
ENV RUN_SERVER_CMD runserver
ENV LDNS_DANE_VALIDATION_DOMAIN internet.nl


# Make port 8080 available to the world outside this container
EXPOSE 8080

# 19.04 is not supported anymore, use old-releases.ubuntu.com for the package maamger.
RUN sed -i -re 's/([a-z]{2}\.)?archive.ubuntu.com|security.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list

# Install required dependencies
# swig is needed to build Unbound with Python bindings
# gettext is needed by python manage.py compilemessages
# libwww-perl is needed by make update_cert_fingerprints
# libssl 1.1.1b was mentioned, without specific reasons. We use a different openssl in checks, so this can be the latest.
# Python 3.7 was mentioned, but the software is also built for later versions. The system version is the one that will
# build unbound the easiest. Other versions are _not_ included in debian/ubuntu by default and will require separate
# builds and steps to get unbound to find the right libraries.
# 18.4 has postgresql 10, not 11. 20.4 has 12. 20.4 uses python 3.8. https://packages.ubuntu.com/focal/python3
# Bison is needed to compile unbound
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install --no-install-recommends -y \
        build-essential \
        curl \
        gcc \
        gettext \
        git \
        ldnsutils \
        libevent-dev \
        libhiredis-dev \
        libssl-dev=1.1.1\* \
        libwww-perl \
        openssl=1.1.1\* \
        postgresql-client-12 \
        postgresql-server-dev-12 \
        python3-gdbm \
        python3 \
        python3-dev \
        python3-pip \
        python3-venv \
        swig3.0 \
        wget \
        bison \
        sudo && \
    rm -rf /var/lib/apt/lists/*

# Create a user for the internetnl app to run as
RUN useradd -ms /bin/bash -G sudo internetnl && echo "internetnl ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/internetnl

# Ensure python 3.7 and pip3 are available as 'python' and 'pip' respectively
# probably not needed anymore given this is the system default...
RUN update-alternatives --install /usr/bin/python python /usr/bin/python3.8 1 && \
    update-alternatives --install /usr/bin/pip pip /usr/bin/pip3 1

# Upgrade pip, and install setuptools (needed below to build Python whois)
RUN pip install --upgrade pip
RUN pip install setuptools

WORKDIR ${APP_PATH}

# Copy our files into the image. Doing this after and separately to installing
# dependencies avoids re-installing dependencies when the set of dependencies
# is unchanged. Do not copy any unneeded files.
# todo: the app source should not be mixed with all kinds of other directories and junk
COPY --chown=internetnl:internetnl .well-known .well-known
COPY --chown=internetnl:internetnl bin bin
COPY --chown=internetnl:internetnl checks checks
COPY --chown=internetnl:internetnl documentation documentation
COPY --chown=internetnl:internetnl frontend frontend
COPY --chown=internetnl:internetnl interface interface
COPY --chown=internetnl:internetnl internetnl internetnl
COPY --chown=internetnl:internetnl remote_data remote_data
COPY --chown=internetnl:internetnl tests tests
COPY --chown=internetnl:internetnl frontend frontend
COPY --chown=internetnl:internetnl translations translations
COPY --chown=internetnl:internetnl Changelog.md Changelog
COPY --chown=internetnl:internetnl LICENSE.spdx LICENSE.spdx
COPY --chown=internetnl:internetnl Makefile Makefile
COPY --chown=internetnl:internetnl manage.py manage.py
COPY --chown=internetnl:internetnl README.md README.md
COPY --chown=internetnl:internetnl requirements.txt requirements.txt
COPY --chown=internetnl:internetnl requirements-dev.txt requirements-dev.txt
COPY --chown=internetnl:internetnl robots.txt robots.txt
COPY --chown=internetnl:internetnl setup.cfg setup.cfg
RUN chown -R internetnl: .

RUN make venv

# Failed to find the swig tool:
RUN ln -s /usr/bin/swig3.0 /usr/bin/swig

# Todo: this will currently not work on arm machines as somehow the build will still say arch -m64 during build.
RUN make nassl_complete
RUN make unbound-3.8
RUN make python-whois

# Cleanup temporary build files
RUN rm -rf nassl_freebsd
RUN rm -rf unbound
RUN rm -rf python-whois

# These manual steps should be the same as in the makefile of the project. Otherise it's basically impossible to maintain.
# Therefore these are replaced with the few make commands above.
# Install forked pythonwhois
# WORKDIR /tmp/build/python-whois
# RUN curl -fsSLo- 'https://github.com/internetstandards/python-whois/tarball/internetnl' | tar zx --strip-components 1
# RUN python setup.py install

# Build nassl from sources for deprecated protocol support and "extra features" compared to the stock package
# Don't be misled by the 1.0.2e and master directory names for OpenSSL, these are the names required by the
# NASSL build process and don't accurately reflect the versions of OpenSSL used, for that look at the versions
# downloaded from GitHub by the commands below.
# WORKDIR /tmp/build/nassl_free_bsd
# RUN mkdir -p bin/openssl-legacy/freebsd64 \
#              bin/openssl-modern/freebsd64 \
#              openssl-1.0.2e \
#              openssl-master && \
#     curl -fsSLo- 'https://github.com/internetstandards/nassl/tarball/internetnl' | tar zx --strip-components 1 && \
#     curl -fsSLo- 'https://zlib.net/zlib-1.2.11.tar.gz' | tar zx && \
#     curl -fsSLo- 'https://github.com/PeterMosmans/openssl/tarball/1.0.2-chacha' | tar zx --strip-components 1 -C openssl-1.0.2e && \
#     curl -fsSLo- 'https://github.com/openssl/openssl/archive/OpenSSL_1_1_1c.tar.gz' | tar zx --strip-components 1 -C openssl-master && \
#     python build_from_scratch.py && \
#     python setup.py install

# Unbound
# See: https://github.com/internetstandards/unbound/blob/internetnl/README.md
# TODO: edit internetnl/internetnl.c to match our deployment of Internet.nl
#    ln -s /usr/local/bin/python3.5 /usr/local/bin/python3.5.6 && \
# WORKDIR /tmp/build/unbound
# RUN curl -fsSLo- 'https://github.com/internetstandards/unbound/tarball/internetnl' | tar zx --strip-components 1 && \
#     ln -s /usr/bin/swig3.0 /usr/bin/swig && \
#     ./configure --enable-internetnl --with-pyunbound --with-libevent --with-libhiredis && \
#     make && \
#     make install

# Point unbound-anchor and Python at the standard location for the unbound lib
ENV LD_LIBRARY_PATH /usr/local/lib

# Configure Unbound for use by Internet.nl, in particular so that LDNS-DANE can depend on a resolver that is DNSSEC
# enabled, which might not be true of the host resolver made available by Docker by default.
# The "unbound.conf" was a product from the previous unbound step? Probably from the `make install`.
# The previous version (1.3) did also not contain an unbound conf. So this probably never worked?
WORKDIR /usr/local/etc/unbound
RUN useradd unbound && \
    cp unbound.conf unbound.conf.org && \
    sed -e 's/# auto-trust-anchor-file:/auto-trust-anchor-file:/' \
        -e 's/# control-enable: no/control-enable: yes/' \
        unbound.conf.org > unbound.conf && \
    unbound-control-setup && \
    unbound-anchor || test $? -eq 1 && \
    chown -R unbound: .


USER internetnl

# Prepare translations
WORKDIR ${APP_PATH}
RUN make translations

# Setup the entrypoint command which will be executed when a container built from this image is run
ENTRYPOINT ["/app/docker/entrypoint.sh"]
