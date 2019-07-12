FROM devbase
ENV DEBIAN_FRONTEND noninteractive
ENV APACHE_WITH_LEGACY_OPENSSL no

# Tip: We inherit latest (openssl in $PATH) and legacy OpenSSL
# (/opt/openssl-old) installations from devbase

RUN apt-get update && apt-get install -y --no-install-recommends \
        apache2 \
        libdb-dev \
        libapr1-dev \
        libaprutil1-dev \
        libpcre3-dev \
        m4 \
        nginx \
        socat

# Build the Postfix SMTP server using legacy OpenSSL
RUN useradd postfix && groupadd postdrop
COPY postfix/main.cf /etc/postfix/main.cf
WORKDIR /tmp/build/postfix
RUN curl -fsSLo- 'ftp://ftp.cs.uu.nl/mirror/postfix/postfix-release/official/postfix-3.4.5.tar.gz' | tar zx --strip-components 1 && \
    make makefiles CCARGS="-DUSE_TLS -I/opt/openssl-old/include" AUXLIBS="-L/opt/openssl-old/lib -lssl -lcrypto" && \
    make && make upgrade

# Enable modules in the stock Apache
RUN a2enmod env
RUN a2enmod headers
RUN a2enmod rewrite

# Build Apache 2.4.39 with OpenSSL 1.0.2e (as used by Internet.nl):
WORKDIR /tmp/build/nassl
RUN mkdir -p bin/openssl-legacy/freebsd64 \
             openssl-1.0.2e && \
    curl -fsSLo- 'https://github.com/ximon18/nassl/tarball/994e156' | tar zx --strip-components 1 && \
    curl -fsSLo- 'https://zlib.net/zlib-1.2.11.tar.gz' | tar zx && \
    curl -fsSLo- 'https://github.com/PeterMosmans/openssl/tarball/1.0.2-chacha' | tar zx --strip-components 1 -C openssl-1.0.2e
COPY custom-httpd/build_from_scratch.py .
RUN python build_from_scratch.py
WORKDIR /tmp/build/nassl/bin/openssl-legacy
RUN ln -s linux64 lib

WORKDIR /tmp/build/custom-httpd
RUN curl -fsSLo- 'http://apache.hippo.nl//httpd/httpd-2.4.39.tar.bz2' | tar jx --strip-components 1 && \
    ./configure --prefix=/opt/custom-httpd --with-ssl=/tmp/build/nassl/bin/openssl-legacy --enable-rewrite
RUN make || true
WORKDIR /tmp/build/custom-httpd/support
RUN /usr/share/apr-1.0/build/libtool --silent --mode=link x86_64-linux-gnu-gcc  -pthread            -o ab  ab.lo       /usr/lib/x86_64-linux-gnu/libaprutil-1.la /usr/lib/x86_64-linux-gnu/libapr-1.la -lm -L/tmp/build/nassl/bin/openssl-legacy/lib -lssl -lcrypto -ldl
WORKDIR /tmp/build/custom-httpd
RUN make && make install

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
COPY dh_param_infiles/*.txt /etc/ssl/certs/dh_params/
COPY certs/some.other.domain.der /etc/ssl/certs/ocsp_responses/
COPY custom-httpd/custom-httpd.conf /opt/custom-httpd/

WORKDIR /root
ENTRYPOINT ["/opt/run-apache-server.sh"]