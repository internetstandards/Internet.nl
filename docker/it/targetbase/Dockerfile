FROM devbase
ENV DEBIAN_FRONTEND noninteractive

# Install latest OpenSSL and Apache for serving TLS 1.1, 1.2 and 1.3 with support for SNI, redirects and HSTS headers
# Install latest OpenSSL and NGINX for serving TLS 1.3 with 0-RTT (not supported by Apache). Alternatively use OpenSSL itself for 0-RTT.
RUN apt-get update && apt-get install -y --no-install-recommends \
        apache2 \
        build-essential \
        curl \
        nginx \
        openssl

RUN openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
        -subj "/C=NL/ST=Noord Holland/L=Amsterdam/O=NLnet Labs/CN=*.test.nlnetlabs.nl" \
        -keyout /etc/ssl/private/wildcard.key -out /etc/ssl/certs/wildcard.crt
RUN openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
        -subj "/C=NL/ST=Noord Holland/L=Amsterdam/O=NLnet Labs/CN=tls1213sni.test.nlnetlabs.nl" \
        -keyout /etc/ssl/private/tls1213sni.key -out /etc/ssl/certs/tls1213sni.crt
RUN openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
        -subj "/C=NL/ST=Noord Holland/L=Amsterdam/O=NLnet Labs/CN=default.test.nlnetlabs.nl" \
        -keyout /etc/ssl/private/default.key -out /etc/ssl/certs/default.crt

# Install OpenSSL 1.0.2e for serving SSL v2, SSL v3 and TLS 1.0
WORKDIR /tmp/build/openssl-1.0.2e
RUN curl -fsSLo- 'https://github.com/openssl/openssl/archive/OpenSSL_1_0_2e.tar.gz' | tar zx --strip-components 1 && \
    ./config --prefix=/opt/openssl-1.0.2e && make && make install

RUN rm -Rf /tmp/build

COPY run-server.sh /opt/

RUN a2enmod headers
RUN a2enmod rewrite

WORKDIR /root
ENTRYPOINT ["/opt/run-server.sh"]