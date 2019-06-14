FROM devbase
ENV DEBIAN_FRONTEND noninteractive

# Tip: We inherit latest (openssl in $PATH) and legacy OpenSSL
# (/opt/openssl-old) installations from devbase

RUN apt-get update && apt-get install -y --no-install-recommends \
        apache2 \
        nginx \
        socat

# Enable Apache modules
RUN a2enmod headers
RUN a2enmod rewrite

# Install the certificate authority and linked OCSP server files:
COPY *.sh /opt/
COPY ca-ocsp /opt/ca-ocsp/

# Generate a self-signed certificate so that we can test that Internet.NL
# detects and complains about it. Deliberately use a short RSA key length
# so that Internet.NL also complains about that.
RUN openssl req -new -newkey rsa:1024 -days 365 -nodes -x509 \
        -subj "/C=NL/ST=Noord Holland/L=Amsterdam/O=NLnet Labs/CN=default.test.nlnetlabs.nl" \
        -keyout /etc/ssl/private/default.test.nlnetlabs.nl.key -out /etc/ssl/certs/default.test.nlnetlabs.nl.crt

COPY certs/*.crt /etc/ssl/certs/
COPY certs/*.key /etc/ssl/private/

WORKDIR /root
ENTRYPOINT ["/opt/run-apache-server.sh"]