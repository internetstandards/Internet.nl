ARG PYTHON_VERSION=3.9

# This Dockerfile consists of multiple stages in order to parallize and speed up
# building. It also reduces image size as only build artifacts are copied into
# the final image. As a result we don't really care about cleaning up apt caches
# or build files in the build stages as they get discarded anyways.

# To build/debug specific stages run: `docker build -f docker/Dockerfile --target
# build-unbound .`, to disable parallel builds and output intermediate image
# hashes/log output prefix build command with: `DOCKER_BUILDKIT=0`

# generic stage used by all build stages
FROM debian:bullseye-20230502-slim as build-deps
ARG PYTHON_VERSION

RUN apt update && \
    apt install --no-install-recommends -yqq \
      # generic build dependencies
      build-essential \
      # unbound dependencies
      python${PYTHON_VERSION}-dev \
      python3-distutils \
      python3-pip \
      libssl-dev \
      libevent-dev \
      libhiredis-dev \
      bison \
      # TODO: swig3.0 hard requirements? get from oldstable
      swig \
      # nassl dependencies
      python3-setuptools

FROM build-deps as build-unbound
ARG PYTHON_VERSION

COPY vendor/unbound /src/vendor/unbound
WORKDIR /src/vendor/unbound
RUN ./configure \
  --prefix=/opt/unbound \
  --enable-internetnl \
  --with-pyunbound \
  --with-libevent \
  --with-libhiredis \
  PYTHON_VERSION=${PYTHON_VERSION}
RUN make
RUN make install

FROM build-deps as build-nassl

COPY vendor/nassl /src/vendor/nassl
WORKDIR /src/vendor/nassl

ADD vendor/zlib-1.2.13.tar.gz ./
COPY vendor/openssl-1.0.2e ./openssl-1.0.2e
COPY vendor/openssl-master ./openssl-master

RUN python3 build_from_scratch.py
RUN python3 setup.py install

# intermediate stage with apt and python dependencies
FROM build-deps as build-app-deps

COPY requirements.txt /src/requirements.txt

WORKDIR /src

RUN pip3 install -r requirements.txt

# stage with app dependencies and lint/test depencencies
FROM build-app-deps as linttest-deps
ARG PYTHON_VERSION

COPY requirements-dev.txt /src/requirements-dev.txt

RUN pip3 install -r requirements-dev.txt

# build unbound target
FROM debian:bullseye-20230502-slim as unbound

COPY --from=build-unbound /opt/unbound /opt/unbound

RUN apt update && \
    apt install --no-install-recommends -yqq \
    # unbound dependencies
    libevent-2.1-7 \
    libhiredis0.14 \
    procps \
    ldnsutils \
    openssl \
    expat \
    # for envsubst
    gettext \
    # since this stage ends up in the final image we care about size and remove cache files
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/opt/unbound/sbin:$PATH"

ADD docker/unbound/test-ns.zone.template /opt/unbound/etc/unbound/test-ns.zone.template
ADD docker/unbound/test-ns6.zone.template /opt/unbound/etc/unbound/test-ns6.zone.template

RUN useradd unbound
WORKDIR /opt/unbound/etc/unbound
# persistent DNSSEC key info and zone file mountpoint
RUN mkdir zones/

RUN unbound-control-setup
RUN unbound-anchor || test $? -eq 1

# add entrypoint and configuration for the connection test unbound service
ADD docker/unbound/entrypoint.sh /entrypoint.sh
ADD docker/unbound/unbound.conf.template /opt/unbound/etc/unbound/unbound.conf.template
# add configuration files for the validating and permissive internal resolver services
ADD docker/resolver/entrypoint-resolver.sh /entrypoint-resolver.sh
ADD docker/resolver/resolver-validating.conf.template /opt/unbound/etc/unbound/resolver-validating.conf.template
ADD docker/resolver/resolver-permissive.conf.template /opt/unbound/etc/unbound/resolver-permissive.conf.template
# empty test config file, to be overwritten with volume mount during integration tests
RUN touch /opt/unbound/etc/unbound/test.conf

RUN chown -R unbound /opt/unbound/etc/unbound

USER unbound

ENTRYPOINT ["/entrypoint.sh"]

# build main application image target
FROM debian:bullseye-20230502-slim as build-app
ARG PYTHON_VERSION

RUN apt update && \
    apt install --no-install-recommends -yqq \
    python3 \
    libpython${PYTHON_VERSION} \
    gettext \
    ldnsutils \
    # unbound dependencies
    libevent-2.1-7 \
    libhiredis0.14 \
    # used for healthchecks
    curl \
    # debug tools
    inetutils-ping \
    dnsutils \
    iproute2 \
    # healthcheck
    netcat \
    procps \
    # since this stage ends up in the final image we care about size and remove cache files
    && rm -rf /var/lib/apt/lists/*

# copy unbound library and unbound Python module into image
COPY --from=build-unbound /opt/unbound /opt/unbound
COPY --from=build-unbound /usr/lib/python3/dist-packages/*unbound* /usr/lib/python3/dist-packages/

# copy nassl Python module into image
COPY --from=build-nassl /usr/local/lib/python${PYTHON_VERSION}/dist-packages/nassl-*.egg /usr/local/lib/python${PYTHON_VERSION}/dist-packages/

# copy application dependencies into image
COPY --from=build-app-deps /usr/local/lib/python${PYTHON_VERSION}/dist-packages/ /usr/local/lib/python${PYTHON_VERSION}/dist-packages/
COPY --from=build-app-deps /usr/local/bin/* /usr/local/bin/

# basic verification of installed components
# The python3 package currently installs version 3.9 but that might change with
# OS updates, verify we run the desired Python version.
RUN python3 --version | grep "$PYTHON_VERSION."
RUN /opt/unbound/sbin/unbound -V
RUN python3 -c 'import nassl; print(nassl.__version__)'

COPY docker/worker/entrypoint.sh /entrypoint-worker.sh

WORKDIR /app

RUN chown nobody:nogroup /app
USER nobody:nogroup

# copy all required sources from the application
COPY --chown=nobody:nogroup bin ./bin
COPY --chown=nobody:nogroup manage.py ./
COPY --chown=nobody:nogroup checks ./checks
COPY --chown=nobody:nogroup frontend ./frontend
COPY --chown=nobody:nogroup interface ./interface
COPY --chown=nobody:nogroup internetnl ./internetnl
COPY --chown=nobody:nogroup translations ./translations
COPY --chown=nobody:nogroup remote_data ./remote_data
COPY --chown=nobody:nogroup assets ./assets

ENV LDNS_DANE=/usr/bin/ldns-dane

ENV STATIC_ROOT /app/static

VOLUME /app/batch_results
RUN install -d -m 0755 -o nobody -g nogroup /app/batch_results

# some js/css files use a separate script to generate minimized versions
# storage these in a place for django to find
RUN mkdir -p /app/static_frontend
RUN python3 bin/frontend.py js
RUN python3 bin/frontend.py css

# generate language files
RUN python3 bin/pofiles.py to_django

# use fake version to prevent building the next steps when only the version changes
ENV SETUPTOOLS_SCM_PRETEND_VERSION=0.0.0-build0

# disable secret key check and cache for commands that run standalone tasks
RUN SKIP_SECRET_KEY_CHECK=True CACHE_LOCATION= ENABLE_BATCH= ./manage.py compilemessages
RUN SKIP_SECRET_KEY_CHECK=True CACHE_LOCATION= ENABLE_BATCH= ./manage.py collectstatic --no-input
RUN SKIP_SECRET_KEY_CHECK=True CACHE_LOCATION= ENABLE_BATCH= ./manage.py api_generate_doc

FROM build-app as app

ARG INTERNETNL_VERSION
ENV SETUPTOOLS_SCM_PRETEND_VERSION=$INTERNETNL_VERSION

# define default entrypoint and command
ENTRYPOINT [ "python3", "./manage.py"]
CMD ["runserver", "0.0.0.0:8080"]

# supplement application with unittest, lint dependencies
FROM build-app as linttest
ARG PYTHON_VERSION

USER root

RUN apt update && \
    apt install --no-install-recommends -yqq \
    git \
    make \
    python3-pip \
    docker.io \
    shellcheck \
    # since this stage ends up in the final image we care about size and remove cache files
    && rm -rf /var/lib/apt/lists/*

# copy application dependencies into image
COPY --from=linttest-deps /usr/local/lib/python${PYTHON_VERSION}/dist-packages/ /usr/local/lib/python${PYTHON_VERSION}/dist-packages/
COPY --from=linttest-deps /usr/local/bin/* /usr/local/bin/

RUN mkdir /source
WORKDIR /source
RUN git config --global --add safe.directory '*'
