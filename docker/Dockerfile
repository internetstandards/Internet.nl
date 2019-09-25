FROM ubuntu:19.04

LABEL vendor="NLnet Labs" \
      license="Apache License, Version 2.0"

ARG BRANCH
ENV APP_PATH /app
ENV DEBIAN_FRONTEND noninteractive
ENV BRANCH ${BRANCH:-master}

# Make port 8080 available to the world outside this container
EXPOSE 8080

# Install required dependencies
# swig is needed to build Unbound with Python bindings
# gettext is needed by python manage.py compilemessages
# libwww-perl is needed by make update_cert_fingerprints
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
        libssl-dev=1.1.1b\* \
        libwww-perl \
        openssl=1.1.1b\* \
        postgresql-server-dev-11 \
        python3-gdbm \
        python3.7 \
        python3.7-dev \
        python3-pip \
        swig3.0 \
        sudo && \
    rm -rf /var/lib/apt/lists/*

# Create a user for the internetnl app to run as
RUN useradd -ms /bin/bash -G sudo internetnl && echo "internetnl ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/internetnl

# Ensure python 3.7 and pip3 are available as 'python' and 'pip' respectively
RUN update-alternatives --install /usr/bin/python python /usr/bin/python3.7 1 && \
    update-alternatives --install /usr/bin/pip pip /usr/bin/pip3 1

# Upgrade pip, and install setuptools (needed below to build Python whois)
RUN pip install --upgrade pip
RUN pip install setuptools

# Install forked pythonwhois
WORKDIR /tmp/build/python-whois
RUN curl -fsSLo- 'https://github.com/ralphdolmans/python-whois/tarball/ee546f4' | tar zx --strip-components 1
RUN python setup.py install

# Build nassl from sources for deprecated protocol support and "extra features" compared to the stock package
# Don't be misled by the 1.0.2e and master directory names for OpenSSL, these are the names required by the
# NASSL build process and don't accurately reflect the versions of OpenSSL used, for that look at the versions
# downloaded from GitHub by the commands below.
WORKDIR /tmp/build/nassl_free_bsd
RUN mkdir -p bin/openssl-legacy/freebsd64 \
             bin/openssl-modern/freebsd64 \
             openssl-1.0.2e \
             openssl-master && \
    curl -fsSLo- 'https://github.com/ximon18/nassl/tarball/758723b' | tar zx --strip-components 1 && \
    curl -fsSLo- 'https://zlib.net/zlib-1.2.11.tar.gz' | tar zx && \
    curl -fsSLo- 'https://github.com/PeterMosmans/openssl/tarball/1.0.2-chacha' | tar zx --strip-components 1 -C openssl-1.0.2e && \
    curl -fsSLo- 'https://github.com/openssl/openssl/archive/OpenSSL_1_1_1c.tar.gz' | tar zx --strip-components 1 -C openssl-master && \
    python build_from_scratch.py && \
    python setup.py install

# Unbound
# See: https://github.com/ralphdolmans/unbound/blob/internetnl/README.md
# TODO: edit internetnl/internetnl.c to match our deployment of Internet.nl
#    ln -s /usr/local/bin/python3.5 /usr/local/bin/python3.5.6 && \
WORKDIR /tmp/build/unbound
RUN curl -fsSLo- 'https://github.com/ralphdolmans/unbound/tarball/internetnl' | tar zx --strip-components 1 && \
    patch -p0 -i ./unbound_1.8.0_patch_unsupported_ds.diff && \
    ln -s /usr/bin/swig3.0 /usr/bin/swig && \
    ./configure --enable-internetnl --with-pyunbound --with-libevent --with-libhiredis && \
    make && \
    make install

# Point unbound-anchor and Python at the standard location for the unbound lib
ENV LD_LIBRARY_PATH /usr/local/lib

# Configure Unbound for use by Internet.nl, in particular so that LDNS-DANE can depend on a resolver that is DNSSEC
# enabled, which might not be true of the host resolver made available by Docker by default.
WORKDIR /usr/local/etc/unbound
RUN useradd unbound && \
    cp unbound.conf unbound.conf.org && \
    sed -e 's/# auto-trust-anchor-file:/auto-trust-anchor-file:/' \
        -e 's/# control-enable: no/control-enable: yes/' \
        unbound.conf.org > unbound.conf && \
    unbound-control-setup && \
    unbound-anchor || test $? -eq 1 && \
    chown -R unbound: .

# Cleanup temporary build files
RUN rm -rf /tmp/build

WORKDIR ${APP_PATH}

# Install Internet.nl web application Python dependencies
COPY python-pip-requirements.txt .
RUN pip install --upgrade pip && \
    pip install --trusted-host pypi.python.org -r ./python-pip-requirements.txt

# Copy our files into the image. Doing this after and separately to installing
# dependencies avoids re-installing dependencies when the set of dependencies
# is unchanged.
COPY --chown=internetnl:internetnl . .
RUN chown -R internetnl: .

USER internetnl

# Configure internetnl to know where LDNS-DANE is installed
RUN sed -i -e "s|LDNS_DANE = .*|LDNS_DANE = '/usr/bin/ldns-dane'|g" ${APP_PATH}/internetnl/settings.py-dist
RUN sed -i -e "s|TIME_ZONE = .*|TIME_ZONE = 'UTC'|g" ${APP_PATH}/internetnl/settings.py-dist

# Prepare translations
RUN make translations

# Setup the entrypoint command which will be executed when a container built from this image is run
ENTRYPOINT ["/app/docker/entrypoint.sh"]
