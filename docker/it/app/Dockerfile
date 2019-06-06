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
RUN echo "Base image: nlnetlabs/internetnl:${INTERNETNL_BASE_IMAGE}"

# Install the Gecko driver required by Selenium
WORKDIR /tmp
RUN curl -fsSLo- 'https://github.com/mozilla/geckodriver/releases/download/v0.24.0/geckodriver-v0.24.0-linux64.tar.gz' | tar zx
RUN sudo mv /tmp/geckodriver /usr/local/bin

# Install test suite dependencies
RUN sudo pip install --upgrade pip && \
    sudo pip install \
        coverage \
        coverage-enable-subprocess \
        pytest-progress \
        pytest-selenium \
        gitpython

COPY docker/it/app/entrypoint.sh.it ${APP_PATH}/docker/entrypoint.sh.it
COPY docker/it/app/coverage/coverage-finalize.sh /opt/
COPY docker/it/app/coverage/.coveragerc /app/

COPY tests/it ${APP_PATH}/tests/it/

# Install Chromium and Firefox browsers in order to be able to interact via a
# browser with the deployed Internet.nl application. You may need to grant
# access to your host X server, e.g. with a command like 'xhost +''. You can't
# visit the app website from your host browser because the Internet.nl app is
# deployed inside a closed Docker network and publishing ports has no effect.
# Installing browsers is optional because it increases the build time which is
# annoying if you have no intention of using them but instead only intend to
# consume the integration test report that is generated and written to the host
# via a bind volume mount.
RUN bash -c "if [ '${INSTALL_BROWSERS}' == 'yes' ]; then apt-get update && apt-get install --no-install-recommends -y chromium-browser firefox; fi"

WORKDIR ${APP_PATH}
ENTRYPOINT ["/app/docker/entrypoint.sh.it"]