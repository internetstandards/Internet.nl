FROM devbase
ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        apache2 \
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

COPY run-server.sh /opt/

RUN a2enmod headers
RUN a2enmod rewrite

ENTRYPOINT ["/opt/run-server.sh"]