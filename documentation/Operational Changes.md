# Operational Changes

This document describes operational/deployment changes throughout new versions. This is intended for developers and
hosters.

## Change overview for version 1.7

* The package pythonwhois needs to be manually removed due to [#782](https://github.com/internetstandards/Internet.nl/issues/782)

Based on an existing 1.6 setup:

```bash
# The next steps need a privileged user
sudo su -

# Enable maintenance mode:
# - edit /etc/apache2/sites-available/internet_nl_shared_config.conf
# - uncomment the 503 maintenance errordocument+rewrite at the end
# - reload apache

# Stop all internet.nl services
for i in $(ls -1 /etc/systemd/system/internetnl-*.service); do systemctl stop `basename $i`; done

su - internetnl

# Get the 1.7 sources
cd /opt/internetnl/Internet.nl/
git reset --hard
git fetch
git checkout v1.7.0

# Update the settings file based on the current dist
cp -v internetnl/settings-dist.py internetnl/settings.py

# Add SENTRY_DSN and SENTRY_ENVIRONMENT to env file
# SENTRY_DSN is secret
echo 'SENTRY_DSN=....' >> ~/internet.nl.env
echo 'SENTRY_ENVIRONMENT=production' >> ~/internet.nl.env

# Update the systemd file for the new settings
cp -v ~/internet.nl.env ~/internet.nl.systemd.env
sed -i 's/\export //g'  ~/internet.nl.systemd.env
mv ~/internet.nl.systemd.env /opt/internetnl/etc/internet.nl.systemd.env

# Upgrade dependencies, run migrations and rebuild the frontend
source ~internetnl/internet.nl.env
# Use a direct PostgreSQL connection instead of bouncer to prevent migration timeouts
export DB_PORT=5432
.venv/bin/pip install -U pip
.venv/bin/pip uninstall pythonwhois
.venv/bin/pip install -Ur requirements.txt
make manage migrate
make frontend

# (exit back to root shell)

# Deploy new configs (changed env file)
cp -v /opt/internetnl/Internet.nl/documentation/example_configuration/opt_internetnl_etc/* /opt/internetnl/etc/

# Restart services, depending if this a batch or single instance server:
systemctl daemon-reload
service internetnl-gunicorn restart
service internetnl-unbound restart

# Single:
for i in $(ls -1 /etc/systemd/system/internetnl-single*.service); do systemctl enable `basename $i` --now; done
for i in $(ls -1 /etc/systemd/system/internetnl-batch*.service); do systemctl disable `basename $i` --now; done

# Batch:
for i in $(ls -1 /etc/systemd/system/internetnl-batch*.service); do systemctl enable `basename $i` --now; done
for i in $(ls -1 /etc/systemd/system/internetnl-single*.service); do systemctl disable `basename $i` --now; done

# Verify services are running
# You should see postgresql, redis-server, rabbitmq-server and various internetnl services, next to standard stuff.
systemctl list-units --type=service

# Disable maintenance mode:
# - edit /etc/apache2/sites-available/internet_nl_shared_config.conf
# - comment out the 503 maintenance errordocument+rewrite at the end
# - reload apache

# In case services failed to start, you can start debugging using these commands:
tail -f /opt/internetnl/log/*
journalctl -xe

# Done! :)
```

## Change overview for version 1.6(.2)

Based on an existing 1.5.x setup or 1.6 setup that you are upgrading to 1.6.2:

```bash
# The next steps need a privileged user
sudo su -

# Enable maintenance mode:
# - edit /etc/apache2/sites-available/internet_nl_shared_config.conf
# - uncomment the 503 maintenance errordocument+rewrite at the end
# - reload apache

# Stop all internet.nl services
for i in $(ls -1 /etc/systemd/system/internetnl-*.service); do systemctl stop `basename $i`; done

su - internetnl

# Get the 1.6.1 sources
cd /opt/internetnl/Internet.nl/
git reset --hard
git fetch
git checkout v1.6.2

# Upgrade dependencies, run migrations and rebuild the frontend
source ~internetnl/internet.nl.env
# Use a direct PostgreSQL connection instead of bouncer to prevent migration timeouts
export DB_PORT=5432

.venv/bin/pip install -Ur requirements.txt
make manage migrate
make frontend

# (exit back to root shell)

# Deploy new configs (changed celery queue conigs)
cp -v /opt/internetnl/Internet.nl/documentation/example_configuration/opt_internetnl_etc/* /opt/internetnl/etc/

# Restart services, depending if this a batch or single instance server:
systemctl daemon-reload
service internetnl-gunicorn restart
service internetnl-unbound restart

# Single:
for i in $(ls -1 /etc/systemd/system/internetnl-single*.service); do systemctl enable `basename $i` --now; done
for i in $(ls -1 /etc/systemd/system/internetnl-batch*.service); do systemctl disable `basename $i` --now; done

# Batch:
for i in $(ls -1 /etc/systemd/system/internetnl-batch*.service); do systemctl enable `basename $i` --now; done
for i in $(ls -1 /etc/systemd/system/internetnl-single*.service); do systemctl disable `basename $i` --now; done

# Verify services are running
# You should see postgresql, redis-server, rabbitmq-server and various internetnl services, next to standard stuff.
systemctl list-units --type=service

# Disable maintenance mode:
# - edit /etc/apache2/sites-available/internet_nl_shared_config.conf
# - comment out the 503 maintenance errordocument+rewrite at the end
# - reload apache

# In case services failed to start, you can start debugging using these commands:
tail -f /opt/internetnl/log/*
journalctl -xe

# Done! :)
```

## Change overview for version 1.5.1

These steps are only needed when upgrading from 1.5.0 to 1.5.1 - if you upgrade
from 1.4.x to 1.5.1 or later, these steps are already included.

Then, based on an existing 1.5.0 setup:

```bash
# The next steps need a privileged user
sudo su -

su - internetnl

# Get the 1.5.1 sources
cd /opt/internetnl/Internet.nl/
git fetch
git checkout v1.5.1

# Regenerate the content files
source ~internetnl/internet.nl.env
make frontend

# (exit back to root shell)

# Restart
service internetnl-gunicorn restart

# Verify gunicorn is running
systemctl status internetnl-gunicorn

# In case services failed to start, you can start debugging using these commands:
tail -f /opt/internetnl/log/*
journalctl -xe

# Done! :)
```

## Change overview for version 1.5

Version 1.5 adds [RPKI validation](rpki.md) as the major new feature.
The overall architecture has remained the same.

To upgrade, first [install Routinator](Installation.md). This may take an hour to
initialise, and can be safely done far before the rest of the upgrade.

Then, based on an existing 1.4 setup:

```bash
# The next steps need a privileged user
sudo su -

# Enable maintenance mode:
# - edit /etc/apache2/sites-available/internet_nl_shared_config.conf
# - uncomment the 503 maintenance errordocument+rewrite at the end
# - reload apache

# Stop all internet.nl services
for i in $(ls -1 /etc/systemd/system/internetnl-*.service); do systemctl stop `basename $i`; done

sudo -s -u internetnl

# Get the 1.5 sources
cd /opt/internetnl/Internet.nl/
git reset --hard
git fetch
git checkout v1.5.0

# Backup the existing configuration, as that will be overwritten
cp -v internetnl/settings.py ~/settings_1.4.py

# Create a new settings file based on the current dist
cp -v internetnl/settings-dist.py internetnl/settings.py

# Update batch API conf from defaults
cp -v internetnl/batch_api_doc_conf_dist.py internetnl/batch_api_doc_conf.py

# NOTE: routinator HTTP API may run on port 9556 or on port 8323 - see our
# Routinator installation documentation
# Test with a curl call to this URL, which should produce "Not Found", meaning
# there is an HTTP API on the endpoint.
echo 'ROUTINATOR_URL=http://localhost:8323/api/v1/validity' >> ~/internet.nl.env
# or
echo 'ROUTINATOR_URL=http://localhost:9556/api/v1/validity' >> ~/internet.nl.env

# The internetnl user also needs these settings. They are loaded through the EnvironmentFile instruction in the
# systemd services. The syntax is a bit different compared to including this for a user. So what we do is:
cp -v ~/internet.nl.env ~/internet.nl.systemd.env
sed -i 's/\export //g'  ~/internet.nl.systemd.env
mv ~/internet.nl.systemd.env /opt/internetnl/etc/internet.nl.systemd.env

# Upgrade dependencies, run migrations and rebuild the frontend
source ~internetnl/internet.nl.env
.venv/bin/pip install -Ur requirements.txt
make manage migrate
make frontend

# <<<exit internetnl shell and return to root>>>

# Deploy new configs (new celery queue)
cp -v /opt/internetnl/Internet.nl/documentation/example_configuration/opt_internetnl_etc/* /opt/internetnl/etc/

# Restart services, depending if this a batch or single instance server:
systemctl daemon-reload
service internetnl-gunicorn restart
service internetnl-unbound restart

# Single:
for i in $(ls -1 /etc/systemd/system/internetnl-single*.service); do systemctl enable `basename $i` --now; done
for i in $(ls -1 /etc/systemd/system/internetnl-batch*.service); do systemctl disable `basename $i` --now; done

# Batch:
for i in $(ls -1 /etc/systemd/system/internetnl-batch*.service); do systemctl enable `basename $i` --now; done
for i in $(ls -1 /etc/systemd/system/internetnl-single*.service); do systemctl disable `basename $i` --now; done

# Verify services are running
# You should see postgresql, redis-server, rabbitmq-server and various internetnl services, next to standard stuff.
systemctl list-units --type=service

# Disable maintenance mode:
# - edit /etc/apache2/sites-available/internet_nl_shared_config.conf
# - comment out the 503 maintenance errordocument+rewrite at the end
# - reload apache

# In case services failed to start, you can start debugging using these commands:
tail -f /opt/internetnl/log/*
journalctl -xe

# Done! :)
```


## Change overview for version 1.4

### Deployment instructions

What you need:
* A copy of the previous settings file, to migrate settings from (especially passwords).
* Know if this is a single or batch installation internet.nl, can't be both. (Impacts the ENABLE BATCH and services)
* Python 3.7 in the command line for unbound compilation

The installation is pretty involved, as we're moving away from changes to the settings.py file and using environment
variables. This is convenient for automated deployment of the app in the future (think ansible etc).

As an in-between patch an environment file is provided which requires you to set up the settings as they were before.
One of the steps in these instructions below copies the settings.py file to a backup location so your passwords can
be retrieved.

```bash
# The next step need a privileged user
sudo su -
# Stop all internet.nl services
for i in $(ls -1 /etc/systemd/system/internetnl-*.service); do systemctl stop `basename $i`; done

sudo su - internetnl

# Get latest sources
cd /opt/internetnl/Internet.nl/

# Backup the existing configuration, as that will be overwritten
cp -v internetnl/settings.py ~/settings_1.3.py

# Clean any manual modifications and untracked files
git reset HEAD --hard
git clean -fdx
git pull
git checkout main

# Create a new settings file
cp -v internetnl/settings-dist.py internetnl/settings.py

# You can now either change the defaults in the settings.py file or use the ENV file supplied.
cp -v internetnl/internet.nl.dist.env ~/internet.nl.env

# Setup the password and such correctly in the env file:
# The following is setup for dev.internet.nl
sed -i "s/SECRET_KEY=.*/SECRET_KEY=secret/g" ~/internet.nl.env
sed -i "s/DB_USER=.*/DB_USER=internetnl/g" ~/internet.nl.env
sed -i "s/DB_PASSWORD=.*/DB_PASSWORD=secret/g" ~/internet.nl.env
sed -i "s/IPV6_TEST_ADDR=.*/IPV6_TEST_ADDR=2a00:d00:ff:162:62:204:66:15/g" ~/internet.nl.env
sed -i "s/CONN_TEST_DOMAIN=.*/CONN_TEST_DOMAIN=dev.internet.nl/g" ~/internet.nl.env
sed -i "s/CSP_DEFAULT_SRC=.*/CSP_DEFAULT_SRC='self',dev.internet.nl/g" ~/internet.nl.env
sed -i "s/SMTP_EHLO_DOMAIN=.*/SMTP_EHLO_DOMAIN=dev.internet.nl/g" ~/internet.nl.env
sed -i "s/ALLOWED_HOSTS=.*/ALLOWED_HOSTS=localhost,dev.internet.nl,.dev.internet.nl/g" ~/internet.nl.env
sed -i "s/MATOMO_SITEID=.*/MATOMO_SITEID=10/g" ~/internet.nl.env
sed -i "s/ENABLE_BATCH=.*/ENABLE_BATCH=False/g" ~/internet.nl.env
sed -i "s/UNBOUND_ADDRESS=.*/UNBOUND_ADDRESS=127.0.0.1@53/g" ~/internet.nl.env

# this environment uses pgbouncer, you might use the default port 5432
sed -i "s/DB_PORT=.*/DB_PORT=6432/g" ~/internet.nl.env

# Always load the env file for this user
echo "source ~/internet.nl.env" >>~/.profile

# Load the file now, in this session:
source ~/internet.nl.env

# The internetnl user also needs these settings. They are loaded through the EnvironmentFile instruction in the
# systemd services. The syntax is a bit different compared to including this for a user. So what we do is:
cp -v ~/internet.nl.env ~/internet.nl.systemd.env
sed -i 's/\export //g'  ~/internet.nl.systemd.env
mv ~/internet.nl.systemd.env /opt/internetnl/etc/internet.nl.systemd.env
chown internetnl:internetnl /opt/internetnl/etc/internet.nl.systemd.env

# Setup the environment and dependencies
make venv
make unbound-3.7-github
make python-whois
make nassl

# Run migrations
make manage migrate

sudo su -
# Deploy new services
rm /etc/systemd/system/internetnl*
cp -v documentation/example_configuration/etc_systemd_system/* /etc/systemd/system/
cp -v documentation/example_configuration/opt_internetnl_etc/batch-* /opt/internetnl/etc/
cp -v documentation/example_configuration/opt_internetnl_etc/single-* /opt/internetnl/etc/
cp -v documentation/example_configuration/opt_internetnl_bin/gunicorn /opt/internetnl/bin/

# Copy the unbound configuration settings from 1.3 to the newly compiled directory (this is not ideal)
cp -ravi /opt/internetnl/unbound/etc/unbound/* /opt/internetnl/Internet.nl/_unbound/etc/unbound/ 


# Restart services, depending if this a batch or single instance server:
systemctl daemon-reload
service internetnl-gunicorn restart
service internetnl-unbound restart

# Single:
# todo: add --now to start now.
for i in $(ls -1 /etc/systemd/system/internetnl-single*.service); do systemctl enable `basename $i`; done
for i in $(ls -1 /etc/systemd/system/internetnl-single*.service); do systemctl restart `basename $i`; done
for i in $(ls -1 /etc/systemd/system/internetnl-batch*.service); do systemctl disable `basename $i`; done

# Batch:
for i in $(ls -1 /etc/systemd/system/internetnl-batch*.service); do systemctl enable `basename $i`; done
for i in $(ls -1 /etc/systemd/system/internetnl-batch*.service); do systemctl restart `basename $i`; done
for i in $(ls -1 /etc/systemd/system/internetnl-single*.service); do systemctl disable `basename $i`; done

# Verify services are running
# You should see postgresql, redis-server, rabbitmq-server and various internetnl services, next to standard stuff.
systemctl list-units --type=service

# In case services failed to start, you can start debugging using these commands:
tail -f /opt/internetnl/log/*
journalctl -xe

# If your system runs out of memory, consider reducing the amount of workers in /opt/internetnl/etc/...-celery-workers
# 10 workers consume about 1 to 2 gigabyte of ram. You can do so by stopping the workers service, altering the config 
# file and restarting it again.

# The site might look bad, so you need to run some translations and such:
sudo su internetnl
make frontend


sudo su -
# An annoying bug is causing redis backend connection leaks. This issue is persistent with the most trivial of tasks
# and opens tons of connections to redis, but not closing all of them properly. Over time this means that the
# system will run out of file handles (the default is 1024). The below fix ups the number of open file handles
# to something ridiculous. It also configures redis to drop connections after a while so redis will not get clogged.

# The file handle limits are already in the systemd services for the single scanner. It is not needed to add these to
# the batch it seems, as this does not occur there (at least we did not see that happen).

# Note: this file might not work for your redis. Just replace timeout to 300 instead of 0 in the existing config file.
# cp -v documentation/example_configuration/etc_redis/redis.conf /etc/redis/redis.conf
cp -v documentation/example_configuration/etc_security/limits.conf /etc/security/limits.conf

# As root:
# Deploy the restart scripts to the proper location:
mkdir /opt/internetnl/etc/cron
cp -v documentation/example_configuration/opt_internetnl_etc/cron/* /opt/internetnl/etc/cron
chmod +x /opt/internetnl/etc/cron/*

# See examples for single scans in: /opt/internetnl/etc/cron/single_crontab
# See examples for batch scans in: /opt/internetnl/etc/cron/batch_crontab


# Scans started during this service reboot will continue, but take a bit longer.

# View logs with:
tail -f /opt/internetnl/log/*log /opt/internetnl/log/*log.1 /var/log/*.log /var/log/*.log.1


# The Apache webserver config has been optimized and updated: 
# - with aggressive caching on the /static/ files.
# - with security.txt being served
# - Single place to manage access limitations and shared settings
sudo su -
a2enmod expires
cp -v documentation/example_configuration/etc_apache2_sites-available/internet_nl* /etc/apache2/sites-available/

# Remove the old config file and pointer and replace it with the new one
rm /etc/apache2/sites-available/internetnl.conf
rm /etc/apache2/sites-enabled/internetnl.conf
ln -s /etc/apache2/sites-available/internet_nl.conf /etc/apache2/sites-enabled/internet_nl.conf
apachectl configtest
service apache2 restart

# Visit the site and verify there are no errors:
tail -f /var/log/apache2/*.log /var/log/apache2/*.log.1

# Done! :)
```


### Changing variables manually
todo: this can be added to the makefile as well, which simplifies rolling this out.
```bash
# Make sure you have the latest config file:
cp internetnl/settings-dist.py internetnl/settings.py


# Edit the ~/internet.nl.env file and add what you need, for example at line 65:
## LDNS Dane
### String, system path to ldns-dane executable or ldns-wrapper file with substituted paths.
export LDNS_DANE=/usr/local/bin/ldns-dane

# Load it into your environment
source ~/internet.nl.env

# And prepare it for the internet.nl services
cp ~/internet.nl.env ~/internet.nl.systemd.env
sed -i 's/\export //g'  ~/internet.nl.systemd.env
mv ~/internet.nl.systemd.env /opt/internetnl/etc/internet.nl.systemd.env
chown internetnl:internetnl /opt/internetnl/etc/internet.nl.systemd.env

# Restart the services:
# single:
for i in $(ls -1 /etc/systemd/system/internetnl-single*.service); do systemctl restart `basename $i`; done
# batch
for i in $(ls -1 /etc/systemd/system/internetnl-batch*.service); do systemctl restart `basename $i`; done
```

Todo: ship an unbound configuration.



### Python installation management
The makefile is 'the way to go' for running and installing the application. Inside the makefile there are a bunch
of automated procedures that supersede the manual sets from the [Installation.md](Installation.md) file. 

The makefile is the point of truth to set up and manage the virtual environment and dependencies 
(unbound, python-whois and nassl).

To setup a complete virtual environment with all needed dependencies run the following:
```bash

make venv
make unbound-37
make python-whois
make nassl
```

The results of these operations are stored in the [.venv](../.venv) directory inside this software directory.

This approach will probably change a bit in the future, but for now this is a surefire way to get a stable environment
up and running in no time.

If your environment was destroyed or something weird is happening, just `make clean` and start over.


### Python dependency management

Python dependencies are now managed with [pip-tools](https://github.com/jazzband/pip-tools/).

Dive into pip-tools and the pip-tools commands in the makefile to figure out how to upgrade dependencies. Note that, 
the manual dependencies above (unbound ...) need to be re-installed after running pip-sync. This has not yet been 
automated away due to time constraints.

The requirements.txt is now a product of pip-tools, and the high-level requirements are maintained in requirements.in.
Do not make manual changes to requirements.txt: it will land you in dependency hell.


### System Services
The [example configuration](example_configuration) folder now includes explicit separate service for daemonizing your
installation. There is a split between 'batch' and 'single' services. The single services are used for the normal
internet.nl website, while the batch services are only needed to run the batch/api deployment.

The folder structure used is explained in the [example configuration readme](example_configuration/readme.md).

Services point to the virtual environment created in the step "Python dependency management".

A new service has been added which handles the scheduler tasks (which are incompatible with gevent). Services and
their instructions are now documented in [Installation.md](Installation.md).


### Manual installation test tooling
Some simple tools have been added to check your installation. Which are:

`make manage api_check_ipv6`: performs an ipv6 test against internet.nl. This verifies that unbound is running.
`make manage api_check_rabbit`: performs a test to see if rabbitmq is correctly installed with management module.



### Changes in testing 
You can run `make test` to run the test suite and see the coverage. Run `make tescase case=...` to run a specific testcase.
These testcases should be placed in the 'test' folder in each Django application. New developments are expected to come
with testcases.

Testing is configured in setup.cfg. The test suite outputs an extensive report in the command line, showing where
tests need to be added. At the time of writing test coverage is at 38%, which is a source of risk and bugs.

A test for registering a batch scan has been added as an example.
