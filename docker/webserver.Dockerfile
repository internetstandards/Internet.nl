FROM nginx:1.25.1

RUN apt-get update && apt-get install -y \
  # for htpasswd
  apache2-utils \
  # for gixy install
  python3-venv \
  && rm -rf /var/lib/apt/lists/*

# install nginx config static analysis tool
RUN python3 -m venv /opt/gixy
# https://github.com/yandex/gixy/issues/125
RUN /opt/gixy/bin/pip install gixy==0.1.20 pyparsing==2.4.7

# install certbot
RUN python3 -m venv /opt/certbot
RUN /opt/certbot/bin/pip install certbot==2.6
COPY docker/webserver/certbot.sh /docker-entrypoint.d/certbot.sh

RUN mkdir -p /etc/nginx/htpasswd/
RUN touch /etc/nginx/htpasswd/monitoring.htpasswd

COPY docker/webserver/10-variables.envsh /docker-entrypoint.d/10-variables.envsh
COPY docker/webserver/tls_init.sh /docker-entrypoint.d/tls_init.sh
COPY docker/webserver/authentication.sh /docker-entrypoint.d/authentication.sh

COPY docker/webserver/user_manage_inner.sh /user_manage_inner.sh

RUN mkdir -p /var/www/internet.nl/

COPY robots.txt /var/www/internet.nl/
COPY .well-known/ /var/www/internet.nl/.well-known/
COPY interface/static/favicon.ico /var/www/internet.nl/

COPY docker/webserver/nginx_templates/* /etc/nginx/templates/
COPY docker/webserver/mime.types /etc/nginx/mime.types
