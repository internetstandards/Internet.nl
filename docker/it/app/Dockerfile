FROM nlnetlabs/internetnl:devel
ARG INSTALL_BROWSERS=no

ENV DEBIAN_FRONTEND noninteractive

WORKDIR /tmp
RUN curl -fsSLo- 'https://github.com/mozilla/geckodriver/releases/download/v0.24.0/geckodriver-v0.24.0-linux64.tar.gz' | tar zx
RUN sudo mv /tmp/geckodriver /usr/local/bin

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

WORKDIR /tmp/it-report

WORKDIR ${APP_PATH}/tests/it
COPY tests/it .

RUN if [ "${INSTALL_BROWSERS}" == "yes" ]; then apt-get update && apt-get install --no-install-recommends -y chromium-browser firefox; fi

ENTRYPOINT ["/app/docker/entrypoint.sh.it"]