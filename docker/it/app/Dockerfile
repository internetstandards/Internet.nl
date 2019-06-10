ARG BASE_IMAGE=nlnetlabs/internetnl:devel
FROM ${BASE_IMAGE}

# Capture the name of the base image we are extending in an environment
# variable that will be available at runtime to the integration test suite and
# can be included in the integration test report. ARG BASE_IMAGE has to be
# specified twice due to the following Dockerfile technical detail:
#
#   "An ARG declared before a FROM is outside of a build stage, so it can’t be
#   used in any instruction after a FROM. To use the default value of an ARG
#   declared before the first FROM use an ARG instruction without a value
#   inside of a build stage:"
#
# From: https://docs.docker.com/engine/reference/builder/#understand-how-arg-and-from-interact
ARG BASE_IMAGE
ENV INTERNETNL_BASE_IMAGE=${BASE_IMAGE}
RUN echo "Base image: ${INTERNETNL_BASE_IMAGE}"

# Install the Gecko driver required by Selenium
WORKDIR /tmp
RUN curl -fsSLo- 'https://github.com/mozilla/geckodriver/releases/download/v0.24.0/geckodriver-v0.24.0-linux64.tar.gz' | tar zx
RUN sudo mv /tmp/geckodriver /usr/local/bin

# Install test suite dependencies
RUN sudo -H pip install --upgrade pip && \
    sudo -H pip install \
        coverage \
        coverage-enable-subprocess \
        pytest-progress \
        pytest-selenium \
        gitpython

COPY docker/it/app/entrypoint.sh.it ${APP_PATH}/docker/entrypoint.sh.it
COPY docker/it/app/coverage/coverage-finalize.sh /opt/
COPY docker/it/app/coverage/.coveragerc /app/

COPY tests/it ${APP_PATH}/tests/it/

# Run as root. Many if not most Docker containers run as root, and the Visual
# Studio Code support for developing in a container requires that the container
# user be root.
USER root

# Stop Celery complaining about running as root.
ENV C_FORCE_ROOT="true"

# Install our custom certificate authority certificate in the operating system
# store. The Internet.NL SSL connection code will use it automatically to verify
# the certificates used by the target servers, as these are signed by our test CA.
COPY docker/it/targetbase/ca-ocsp/ca/rootCA.crt /usr/local/share/ca-certificates/internetnl-test/
RUN chmod 755 /usr/local/share/ca-certificates/internetnl-test/ && \
    chmod 644 /usr/local/share/ca-certificates/internetnl-test/rootCA.crt
RUN update-ca-certificates

WORKDIR ${APP_PATH}
ENTRYPOINT ["/app/docker/it/app/entrypoint.sh.it"]