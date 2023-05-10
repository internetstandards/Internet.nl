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

FROM build-deps as build-app-deps

COPY requirements.txt /src/requirements.txt

WORKDIR /src

RUN pip3 install -r requirements.txt

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

RUN ldns-keygen -k -a RSASHA256 test-ns-signed.internet.nl
RUN ldns-keygen -k -a RSASHA256 test-ns6-signed.internet.nl

ADD docker/unbound/test-ns-signed.zone /opt/unbound/etc/unbound/test-ns-signed.zone.template
ADD docker/unbound/test-ns6-signed.zone /opt/unbound/etc/unbound/test-ns6-signed.zone.template

RUN useradd unbound
WORKDIR /opt/unbound/etc/unbound
RUN unbound-control-setup
RUN unbound-anchor || test $? -eq 1

ADD docker/unbound/entrypoint.sh /entrypoint.sh
ADD docker/unbound/unbound.conf /opt/unbound/etc/unbound/unbound.conf

RUN chown -R unbound /opt/unbound/etc/unbound

USER unbound

ADD docker/unbound/entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]

FROM debian:bullseye-20230502-slim as app
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

# TODO: settings file should be parametrized by environment variables
RUN cp internetnl/settings-dist.py internetnl/settings.py

ENV LDNS_DANE=/usr/bin/ldns-dane

ENV STATIC_ROOT /app/static

VOLUME /app/batch_results
RUN install -d -m 0755 -o nobody -g nogroup /app/batch_results

# build all static components for the application
RUN python3 bin/frontend.py js
RUN python3 bin/frontend.py css
RUN python3 bin/pofiles.py to_django
# disable secret key check and cache for commands that run standalone tasks
RUN SKIP_SECRET_KEY_CHECK=True CACHE_LOCATION= ./manage.py compilemessages
RUN SKIP_SECRET_KEY_CHECK=True CACHE_LOCATION= ./manage.py collectstatic --no-input
RUN SKIP_SECRET_KEY_CHECK=True CACHE_LOCATION= ./manage.py api_generate_doc

# basic verification of installed components
# The python3 package currently installs version 3.9 but that might change with
# OS updates, verify we run the desired Python version.
RUN python3 --version | grep "$PYTHON_VERSION."
RUN /opt/unbound/sbin/unbound -V
RUN python3 -c 'import nassl; print(nassl.__version__)'

# define default entrypoint and command
ENTRYPOINT [ "python3", "./manage.py"]
CMD ["runserver", "0.0.0.0:8080"]
