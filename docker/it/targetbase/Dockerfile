FROM devbase
ENV DEBIAN_FRONTEND noninteractive

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
        socat \
        zlib1g-dev

# Enable modules in the stock Apache
RUN a2enmod env
RUN a2enmod headers
RUN a2enmod rewrite

# Build Apache 2.4.39 with modified OpenSSL 1.0.2 with weak security features
# First build OpenSSL
WORKDIR /tmp/build/nassl
RUN mkdir -p bin/openssl-legacy/freebsd64 \
             openssl-1.0.2e && \
    curl -fsSLo- 'https://github.com/internetstandards/nassl/tarball/internetnl' | tar zx --strip-components 1 && \
    curl -fsSLo- 'https://zlib.net/zlib-1.2.11.tar.gz' | tar zx && \
    curl -fsSLo- 'https://github.com/PeterMosmans/openssl/tarball/1.0.2-chacha' | tar zx --strip-components 1 -C openssl-1.0.2e
COPY custom-httpd/build_from_scratch.py .
RUN python build_from_scratch.py
# Create symlinks needed by the Apache build process for -lsso, -lcrypto and
# -lz to resolve correctly.
WORKDIR /tmp/build/nassl/bin/openssl-legacy
RUN ln -s linux64 lib
# Then build Apache using our new OpenSSL
ENV APACHE_SERVERROOT_OPENSSL_LEGACY /opt/apache-2.4-openssl-legacy
WORKDIR /tmp/build/apache-2.4-openssl-legacy
RUN curl -fsSLo- 'https://archive.apache.org/dist/httpd/httpd-2.4.39.tar.bz2' | tar jx --strip-components 1 && \
    ./configure --prefix=${APACHE_SERVERROOT_OPENSSL_LEGACY} \
                --with-ssl=/tmp/build/nassl/bin/openssl-legacy \
                --enable-rewrite
# Build from sources up until the point that the Make fails, then hand fix the
# failing make step by adding missing -L and -l arguments then finally resume
# the build process... there must be a better way, but attempts to resolve the
# issue via configure did not succeed.
RUN make || true
WORKDIR /tmp/build/apache-2.4-openssl-legacy/support
RUN /usr/share/apr-1.0/build/libtool --silent --mode=link x86_64-linux-gnu-gcc -pthread -o ab \
    ab.lo /usr/lib/x86_64-linux-gnu/libaprutil-1.la /usr/lib/x86_64-linux-gnu/libapr-1.la -lm \
    -L/tmp/build/nassl/bin/openssl-legacy/lib -lssl -lcrypto -ldl
WORKDIR /tmp/build/apache-2.4-openssl-legacy
RUN make && make install

# Build Apache 2.4.39 with OpenSSL 1.1.1 with support for ZLib compression
# First build OpenSSL
WORKDIR /tmp/build/openssl-modern
RUN curl -fsSLo- 'https://www.openssl.org/source/openssl-1.1.1c.tar.gz' | tar zx --strip-components 1 && \
    ./config --prefix=/opt/openssl-modern zlib && \
    make && make install_sw
# Then build Apache using our new OpenSSL
ENV APACHE_SERVERROOT_OPENSSL_MODERN /opt/apache-2.4-openssl-modern
WORKDIR /tmp/build/apache-2.4-openssl-modern
RUN curl -fsSLo- 'https://archive.apache.org/dist/httpd/httpd-2.4.39.tar.bz2' | tar jx --strip-components 1 && \
    ./configure --prefix=${APACHE_SERVERROOT_OPENSSL_MODERN} \
                --with-ssl=/opt/openssl-modern \
                --enable-rewrite && \
    make && make install

# Build ancient OpenSSL 0.9.8k for a server that doesn't support secure
# renegotiation (RFC-5746). Building that requires "./config no-asm" to work
# around https://stackoverflow.com/a/14574746 and "make install_sw" to work
# around https://askubuntu.com/a/742712. We also need an old Apache version as
# modern versions reject client initiated renegotiation irrespective of how
# OpenSSL is configured. See:
# https://github.com/apache/httpd/commit/06f68fdc54c72573d4b520219b87a05abb098380
WORKDIR /tmp/build/openssl-ancient
RUN curl -fsSLo- 'https://www.openssl.org/source/old/0.9.x/openssl-0.9.8k.tar.gz' | tar zx --strip-components 1 && \
    CFLAGS=-fPIC ./config --prefix=/opt/openssl-ancient shared no-asm && \
    make && make install_sw
# Then build Apache using our new OpenSSL
ENV APACHE_SERVERROOT_OPENSSL_ANCIENT /opt/apache-2.0-openssl-ancient
WORKDIR /tmp/build/apache-2.0-openssl-ancient
RUN curl -fsSLo- 'https://archive.apache.org/dist/httpd/httpd-2.0.63.tar.bz2' | tar jx --strip-components 1 && \
    ./configure --prefix=${APACHE_SERVERROOT_OPENSSL_ANCIENT} \
                --with-ssl=/opt/openssl-ancient \
                --enable-headers \
                --enable-rewrite \
                --enable-ssl
RUN make && make install

# Build the Postfix SMTP server using legacy OpenSSL
RUN useradd postfix && groupadd postdrop
WORKDIR /tmp/build/postfix
RUN curl -fsSLo- 'https://ftp.cs.uu.nl/mirror/postfix/postfix-release/official/postfix-3.4.5.tar.gz' | tar zx --strip-components 1
ENV POSTFIX_PREFIX_OPENSSL_LEGACY /opt/postfix-old
RUN make clean && \
    make makefiles \
      command_directory=${POSTFIX_PREFIX_OPENSSL_LEGACY}/bin \
      config_directory=${POSTFIX_PREFIX_OPENSSL_LEGACY}/etc \
      daemon_directory=${POSTFIX_PREFIX_OPENSSL_LEGACY}/bin \
      openssl_path=/opt/openssl-old/bin/openssl \
      shlib_directory=${POSTFIX_PREFIX_OPENSSL_LEGACY}/lib \
      CCARGS="-DUSE_TLS -I/opt/openssl-old/include" \
      AUXLIBS="-L/opt/openssl-old/lib -lssl -lcrypto" && \
    make && \
    sh postfix-install -non-interactive

# Build the Postfix SMTP server using modern OpenSSL
ENV POSTFIX_PREFIX_OPENSSL_MODERN /opt/postfix-modern
RUN make clean && \
    make makefiles \
      command_directory=${POSTFIX_PREFIX_OPENSSL_MODERN}/bin \
      config_directory=${POSTFIX_PREFIX_OPENSSL_MODERN}/etc \
      daemon_directory=${POSTFIX_PREFIX_OPENSSL_MODERN}/bin \
      openssl_path=/opt/openssl-modern/bin/openssl \
      shlib_directory=${POSTFIX_PREFIX_OPENSSL_MODERN}/lib \
      CCARGS="-DUSE_TLS -I/opt/openssl-modern/include" \
      AUXLIBS="-L/opt/openssl-modern/lib -lssl -lcrypto" && \
    make && \
    sh postfix-install -non-interactive

# Apply our custom Postfix configuration that is common to all target servers
COPY postfix/postfix-debug.cidrs /etc/
COPY postfix/main.cf ${POSTFIX_PREFIX_OPENSSL_LEGACY}/etc/main.cf
COPY postfix/main.cf ${POSTFIX_PREFIX_OPENSSL_MODERN}/etc/main.cf
RUN POSTFIX_PREFIX=${POSTFIX_PREFIX_OPENSSL_LEGACY} /opt/jinjify.sh ${POSTFIX_PREFIX_OPENSSL_LEGACY}/etc/main.cf
RUN POSTFIX_PREFIX=${POSTFIX_PREFIX_OPENSSL_MODERN} /opt/jinjify.sh ${POSTFIX_PREFIX_OPENSSL_MODERN}/etc/main.cf

# Install the certificate authority and linked OCSP server files:
COPY *.sh /opt/
COPY ca-ocsp /opt/ca-ocsp/

# Generate a self-signed certificate so that we can test that Internet.NL
# detects and complains about it. Deliberately use a short RSA key length
# so that Internet.NL also complains about that.
RUN openssl req -new -newkey rsa:1024 -days 365 -nodes -x509 \
        -subj "/C=NL/ST=Noord Holland/L=Amsterdam/O=NLnet Labs/CN=default.test.nlnetlabs.tk" \
        -keyout /etc/ssl/private/default.test.nlnetlabs.tk.key -out /etc/ssl/certs/default.test.nlnetlabs.tk.crt

COPY certs/*.crt /etc/ssl/certs/
COPY certs/*.key /etc/ssl/private/
COPY dh_param_infiles/*.txt /etc/ssl/certs/dh_params/
COPY certs/some.other.domain.der /etc/ssl/certs/ocsp_responses/
COPY custom-httpd/custom-httpd24.conf ${APACHE_SERVERROOT_OPENSSL_LEGACY}/custom-httpd.conf
COPY custom-httpd/custom-httpd24.conf ${APACHE_SERVERROOT_OPENSSL_MODERN}/custom-httpd.conf
COPY custom-httpd/custom-httpd22.conf ${APACHE_SERVERROOT_OPENSSL_ANCIENT}/custom-httpd.conf
COPY sites-available/* /etc/apache2/sites-available/
COPY html /var/www/html/
RUN SERVER_ROOT=${APACHE_SERVERROOT_OPENSSL_LEGACY} /opt/jinjify.sh ${APACHE_SERVERROOT_OPENSSL_LEGACY}/custom-httpd.conf
RUN SERVER_ROOT=${APACHE_SERVERROOT_OPENSSL_MODERN} /opt/jinjify.sh ${APACHE_SERVERROOT_OPENSSL_MODERN}/custom-httpd.conf
RUN SERVER_ROOT=${APACHE_SERVERROOT_OPENSSL_ANCIENT} /opt/jinjify.sh ${APACHE_SERVERROOT_OPENSSL_ANCIENT}/custom-httpd.conf

COPY postfix/configs-available/* /etc/postfix/configs-available/

WORKDIR /root
ENTRYPOINT ["/opt/run-apache-server.sh"]
