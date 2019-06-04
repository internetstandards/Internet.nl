FROM targetbase
ARG APACHE_SITES
ARG APACHE_MODULES
COPY sites-available/* /etc/apache2/sites-available/
RUN a2dissite 000-default
RUN for M in "${APACHE_MODULES}"; do a2enmod $M; done
RUN for S in "${APACHE_SITES}"; do a2ensite $S; done