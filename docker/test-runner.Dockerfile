ARG PYTHON_VERSION=3.9

FROM mcr.microsoft.com/playwright/python:v1.49.0-noble
ARG PYTHON_VERSION

RUN python3 -m pip install pytest pytest-playwright

RUN install -m 0755 -d /etc/apt/keyrings
RUN curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
RUN chmod a+r /etc/apt/keyrings/docker.gpg
RUN echo "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu "$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

RUN apt-get update && apt-get install -y \
  docker-ce-cli \
  docker-compose-plugin \
  dnsutils \
  iproute2 \
  iputils-ping \
  && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /source
VOLUME /source

COPY integration_tests/ /source/integration_tests/

WORKDIR /source

ENTRYPOINT [ "python3", "-m", "pytest", "--verbose"]
CMD [ "integration_tests/live/" ]