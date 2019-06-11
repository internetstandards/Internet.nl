FROM devbase
ENV DEBIAN_FRONTEND noninteractive

# Install latest OpenSSL and Apache for serving TLS 1.1, 1.2 and 1.3 with support for SNI, redirects, HSTS headers, OCSP stapling, etc.
# Install latest OpenSSL and NGINX for serving TLS 1.3 with 0-RTT (not supported by Apache). Alternatively use OpenSSL itself for 0-RTT.
RUN apt-get update && apt-get install -y --no-install-recommends \
        apache2 \
        build-essential \
        curl \
        nginx \
        openssl

# Install OpenSSL 1.0.2e for serving SSL v2, SSL v3 and TLS 1.0
WORKDIR /tmp/build/openssl-1.0.2e
RUN curl -fsSLo- 'https://github.com/openssl/openssl/archive/OpenSSL_1_0_2e.tar.gz' | tar zx --strip-components 1 && \
    ./config --prefix=/opt/openssl-1.0.2e && make && make install

RUN rm -Rf /tmp/build

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
ENTRYPOINT ["/opt/run-server.sh"]