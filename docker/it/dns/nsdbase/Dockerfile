FROM devbase

# Install NSD
RUN apt-get install -y nsd

# Install our NSD config
RUN mv /etc/nsd /etc/nsd.bak
COPY nsd /etc/nsd/

# Install helper scripts
COPY *.sh /opt/
RUN chmod +x /opt/*.sh

# Configure containers created from this image to replace Jinja2 template fragments and to launch NSD in the foreground
ENTRYPOINT ["/opt/start-nsd.sh"]

ONBUILD COPY nsd /etc/nsd/