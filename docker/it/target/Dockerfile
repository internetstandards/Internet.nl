FROM targetbase
ARG APACHE_SITES=
ARG APACHE_MODULES=

# Disable default Apache website
RUN a2dissite -q 000-default

COPY sites-available/* /etc/apache2/sites-available/
COPY html /var/www/html/

# Enable Apache modules and website configurations as directed by the user invoking Docker build
RUN bash -c 'if [ "${APACHE_MODULES}" != "" ]; then for M in "${APACHE_MODULES}"; do a2enmod -q $M; done; fi'
RUN bash -c 'if [ "${APACHE_SITES}" != "" ]; then for S in "${APACHE_SITES}"; do a2ensite -q $S; done; fi'