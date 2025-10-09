FROM nginx:1.27.3

RUN apt-get update && apt-get install -y \
  # for htpasswd
  apache2-utils \
  # for gixy install
  python3-venv \
  && rm -rf /var/lib/apt/lists/*

# install nginx config static analysis tool
RUN python3 -m venv /opt/gixy
RUN /opt/gixy/bin/pip install gixy==0.1.21

# install certbot
RUN python3 -m venv /opt/certbot
RUN /opt/certbot/bin/pip install certbot==3.0.1
COPY docker/webserver/certbot.sh /docker-entrypoint.d/

RUN mkdir -p /etc/nginx/htpasswd/
RUN touch /etc/nginx/htpasswd/monitoring.htpasswd

COPY docker/webserver/10-variables.envsh /docker-entrypoint.d/
COPY docker/webserver/40-add-mail-include.sh /docker-entrypoint.d/
COPY docker/webserver/tls_init.sh /docker-entrypoint.d/
COPY docker/webserver/authentication.sh /docker-entrypoint.d/
COPY docker/webserver/generate_quic_host_key.sh /docker-entrypoint.d/

COPY docker/webserver/user_manage_inner.sh /

RUN mkdir -p /var/www/internet.nl/

COPY robots.txt /var/www/internet.nl/

RUN mkdir -p /var/www/internet.nl/.well-known/
# copy all security*.txt files
COPY .well-known/security*.txt /var/www/internet.nl/.well-known/
COPY interface/static/favicon.ico /var/www/internet.nl/

COPY docker/webserver/nginx_templates/* /etc/nginx/templates/
COPY docker/webserver/mail_templates/* /etc/nginx/mail_templates/
COPY docker/webserver/mime.types /etc/nginx/
COPY docker/webserver/http.headers /etc/nginx/
COPY docker/webserver/hsts_h3.headers /etc/nginx/
COPY docker/webserver/all.headers /etc/nginx/
