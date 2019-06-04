FROM nlnetlabs/internetnl:devel

ENV DEBIAN_FRONTEND noninteractive

# RUN sudo -E apt-get update && \
#     sudo -E apt-get install --no-install-recommends -y chromium firefox-esr

WORKDIR /tmp
RUN curl -fsSLo- 'https://github.com/mozilla/geckodriver/releases/download/v0.24.0/geckodriver-v0.24.0-linux64.tar.gz' | tar zx
RUN sudo mv /tmp/geckodriver /usr/local/bin

RUN sudo pip install --upgrade pip && \
    sudo pip install \
        pytest-progress \
        pytest-selenium \
        gitpython

COPY docker/it/app/entrypoint.sh.it ${APP_PATH}/docker/entrypoint.sh.it

WORKDIR /tmp/it-report
RUN sudo chown -R internetnl: . && \
    sudo chmod -R a+w .

WORKDIR ${APP_PATH}/tests/it
COPY tests/it .

ENTRYPOINT ["/app/docker/entrypoint.sh.it"]