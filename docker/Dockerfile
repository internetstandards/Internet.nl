FROM python:3.5.6

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
        curl \
        gettext \
        git \
        ldnsutils \
        libhiredis-dev \
        libwww-perl \
        postgresql-server-dev-9.6 \
        swig3.0 \
        sudo && \
    rm -rf /var/lib/apt/lists/*

# Create a user for the internetnl app to run as
RUN useradd -ms /bin/bash -G sudo internetnl && echo "internetnl ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/internetnl

# Install forked pythonwhois
RUN git clone -b timeout https://github.com/ralphdolmans/python-whois.git /tmp/python-whois
WORKDIR /tmp/python-whois
RUN python setup.py install

# Build nassl from sources for deprecated protocol support and "extra features" compared to the stock package
RUN git clone -b free_bsd https://github.com/gthess/nassl.git /tmp/nassl_freebsd
WORKDIR /tmp/nassl_freebsd
RUN mkdir -p bin/openssl-legacy/freebsd64 && mkdir -p bin/openssl-modern/freebsd64
RUN curl https://zlib.net/zlib-1.2.11.tar.gz | tar zx && \
    git clone -b 1.0.2-chacha https://github.com/PeterMosmans/openssl.git openssl-1.0.2e && \
    git clone https://github.com/openssl/openssl.git openssl-master && \
    cd openssl-master && \
    git checkout 1f5878b8e25a785dde330bf485e6ed5a6ae09a1a && \
    cd .. && \
    python build_from_scratch.py && \
    python setup.py install

# Unbound
# See: https://github.com/ralphdolmans/unbound/blob/internetnl/README.md
# TODO: edit internetnl/internetnl.c to match our deployment of Internet.nl
RUN git clone -b internetnl https://github.com/ralphdolmans/unbound.git /tmp/unbound
WORKDIR /tmp/unbound
RUN patch -p0 -i ./unbound_1.8.0_patch_unsupported_ds.diff && \
    ln -s /usr/local/bin/python3.5 /usr/local/bin/python3.5.6 && \
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

WORKDIR ${APP_PATH}
#RUN chown -R internetnl:internetnl ${APP_PATH}

# Fetch the Internet.nl web application files and install Python dependencies
COPY --chown=internetnl:internetnl . ${APP_PATH}
RUN chown -R internetnl: ${APP_PATH}
RUN pip install --trusted-host pypi.python.org -r ./python-pip-requirements.txt

USER internetnl

# Configure internetnl to know where LDNS-DANE is installed
RUN sed -i -e "s|LDNS_DANE = .*|LDNS_DANE = '/usr/bin/ldns-dane'|g" ${APP_PATH}/internetnl/settings.py-dist

# Prepare translations
RUN make translations

# Cleanup
RUN sudo rm -rf ${APP_PATH}/.git /tmp/unbound /tmp/nassl_freebsd /tmp/python-whois

# Setup the entrypoint command which will be executed when a container built from this image is run
ENTRYPOINT ${APP_PATH}/docker/entrypoint.sh
