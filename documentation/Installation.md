# Installation

Internet.nl is a [Django](https://www.djangoproject.com/)
based application and therefore inherits its requirements.

Current install base is Django 3.2 LTS with Python 3.7.

The following instructions should work on most Debian-based systems. Tested on Ubuntu 18.04

## System requirements

Install the following system requirements:

`apt install git python3 python3-pip build-essential libssl-dev libffi-dev python-dev postgresql postgresql-server-dev-all swig libevent-dev libhiredis-dev redis-server rabbitmq-server bison python3-venv`

## Software

### Python 3

Create a virtual environment with: 
`make venv`

Add the custom python-whois with:
`make pythonwhois`


[//]: # (Old / outdated instructions:)
[//]: # (_Setting up a Python virtual environment is **highly recommended**._)
[//]: # (Follow the instructions at the)
[//]: # (official Python documentation](https://docs.python.org/3/tutorial/venv.html)
[//]: # (and make sure that the environment is always activated when interacting with)
[//]: # (internet.nl's installation.)
[//]: # ()
[//]: # (Install all Python dependencies from pip at once:)
[//]: # (* `pip install -r requirements.txt`)
[//]: # ()
[//]: # (Install Python dependencies not in pip:)
[//]: # (* pythonwhois (use fork at https://github.com/internetstandards/python-whois/tree/internetnl)
[//]: # (   ```)
[//]: # (   git clone https://github.com/internetstandards/python-whois.git)
[//]: # (   cd python-whois)
[//]: # (   git checkout internetnl)
[//]: # (   python setup.py install)
[//]: # (   ```)


### nassl

Install with:
`make nassl`

[//]: # (Old / outdated instructions:)
[//]: # (nassl](https://github.com/nabla-c0d3/nassl is an OpenSSL wrapper and is used)
[//]: # (in the various TLS related tests in the website and mail tests.)
[//]: # ()
[//]: # (A fork is used to facilitate installation on freeBSD systems.)
[//]: # ()
[//]: # (1. Clone nassl use fork at https://github.com/internetstandards/nassl/tree/internetnl)
[//]: # (   ```)
[//]: # (   git clone https://github.com/internetstandards/nassl.git nassl_freebsd)
[//]: # (   cd nassl_freebsd)
[//]: # (   git checkout internetnl)
[//]: # (   mkdir -p bin/openssl-legacy/freebsd64)
[//]: # (   mkdir -p bin/openssl-modern/freebsd64)
[//]: # (   ```)
[//]: # ()
[//]: # (2. Download zlib needed for building legacy openssl)
[//]: # (   ```)
[//]: # (   wget http://zlib.net/zlib-1.2.11.tar.gz)
[//]: # (   tar xvfz  zlib-1.2.11.tar.gz)
[//]: # (   ```)
[//]: # ()
[//]: # (3. Clone PeterMosmans openssl fork inside nassl's directory)
[//]: # (   ```)
[//]: # (   git clone https://github.com/PeterMosmans/openssl.git openssl-1.0.2e)
[//]: # (   cd openssl-1.0.2e; git checkout 1.0.2-chacha; cd ..)
[//]: # (   ```)
[//]: # ()
[//]: # (4.  Clone openssl inside nassl's directory)
[//]: # (   ```)
[//]: # (   git clone https://github.com/openssl/openssl.git openssl-master)
[//]: # (   cd openssl-master; git checkout OpenSSL_1_1_1c; cd ..)
[//]: # (   ```)
[//]: # ()
[//]: # (5. Build nassl)
[//]: # (   `python build_from_scratch.py`)
[//]: # ()
[//]: # (6. Install nassl)
[//]: # (   `python setup.py install`)


### Redis

Redis is used for Django caching and Celery result backend
`apt install redis-server`


### RabbitMQ

Rabbitmq is used as the broker for Celery
`apt install rabbitmq-server`

For Batch support: Install the management plugin for rabbit:
`rabbitmq-plugins enable rabbitmq_management`

See: https://www.rabbitmq.com/management.html


### Unbound

Install for python 3.7 with:
`make unbound-37`

Unbound (and pylibunbound) is used as a DNS resolver/nameserver for the various
tests performed.

Use the fork at https://github.com/internetstandards/unbound.git
Make sure to use the `internetnl` branch and follow the
[README.md](https://github.com/internetstandards/unbound/blob/internetnl/README.md)
instructions for installation.

If you setup a python virtual environment you should enable it for unbound's
installation.

_Note that extra DNS records are needed._


### ldns-dane

ldns-dane is an example application from the ldns library that validates a
domain's DANE record(s) and is used for validating the DANE records in the
website and mail tests.

_Note that ldns-dane will use your locally configured DNS resolver to get
and validate the TLSA records. This means that your locally configured DNS
resolver needs to have DNSSEC enabled._

If your system has ldns >= 1.7.0 **and** openssl >= 1.1.0 you are good to go.

If not:
- Compile openssl
  - Get an openssl version >= 1.1.0 from [here](https://www.openssl.org/source/)
  - `./config --prefix=/path/to/local/ssl/build/dir --openssldir=/same/as/prefix/`
  - `make && make test && make install`
- Compile ldns
  - Get an ldns version >= 1.7.0 from [here](https://www.nlnetlabs.nl/projects/ldns/download/)
  - `./configure --with-examples --with-ssl=/path/to/above/ssl/build/dir`
  - `make`
- Create a wrapper file for using the compiled ldns-dane binary
  `cat ldns-dane-wrapper`
  ```
  #!/bin/sh
  # Wrapper for non-installed ldns-dane, compiled with non-system openssl version.

  OPENSSL_LIB_PATH=/path/to/local/ssl/build/dir/lib
  LDNS_LIB_PATH=/path/to/ldns-1.7.0/lib
  LDNS_DANE_PATH=/path/to/ldns-1.7.0/examples/.libs/ldns-dane
  LDNS_DANE_ARGS="$@"

  LD_LIBRARY_PATH=$OPENSSL_LIB_PATH:$LDNS_LIB_PATH
  export LD_LIBRARY_PATH
  $LDNS_DANE_PATH $LDNS_DANE_ARGS
  RETURN_VALUE=$?
  unset LD_LIBRARY_PATH
  exit $RETURN_VALUE
  ```
- Update the `LDNS_DANE` option in Django's settings to point to the
  `ldns-dane-wrapper` file above.


### PostgreSQL

PostgreSQL is used as the database.
`apt install postgresql-server-dev-9.5`

- Create postgres user and database:
  * `sudo -u postgres createuser <username> -P`
  * `sudo -u postgres createdb -O <username> <db_name>`

If you expect high DB traffic the use of
[PgBouncer](https://pgbouncer.github.io/) is recommended as a connection pooler
for PostgreSQL.


## Django setup

- Copy distributed config and edit:
  * `cp internetnl/settings.py-dist internetnl/settings.py`
  * Review the settings and make sure to at least change secret, database
    settings, redis settings, celery settings, ldns-dane location
- Apply the DB schema and/or migrations:
  ```
  python manage.py migrate checks
  ```


## Running services

Make sure the following services are installed and running on your system:
- Redis
  _should be installed by the previous steps_
- RabbitMQ
  _should be installed by the previous steps_
- Unbound

- Celery and celery beat
  These services need to be setup manually. You can follow [these](http://docs.celeryproject.org/en/latest/userguide/daemonizing.html)
  instructions and consult the [example configuration files](example_configuration/).
  The example configuration files are included for systemd and should be placed in the correct directories.
  

The basics of the celery and celery beat services:

* List all services: systemctl list-units --type=service
* service internetnl-celery restart
* service internetnl-celery-beat restart
* service internetnl-gunicorn restart
* service internetnl-unbound restart
 
If things don't happen, you can inspect the current queues with:
`rabbitmqctl list_queues`

And you can see what workers are running in memory with:
`ps aux | grep python`

Restart all internetnl services:
* `for i in $(ls -1 /etc/systemd/system/internetnl-*.service); do systemctl restart `basename $i`; done`



## DNS records

The `<base-domain>` should contain the following domain names pointing to the
IP addresses of the webserver (the default `<base-domain>` is `internet.nl`):
 - `<base-domain>`
 - `en`.`<base-domain>`
 - `nl`.`<base-domain>`
 - `www`.`<base-domain>`
 - `conn`.`<base-domain>`
 - `en`.`conn`.`<base-domain>`
 - `nl`.`conn`.`<base-domain>`

The `<base-domain>` should contain delegations and DS records for the following
names (see the Unbound section for more information):
 - test-ns-signed.`<base-domain>`
 - test-ns6-signed.`<base-domain>`

### I18N consideration

The internet.nl site tries to avoid the recording of any session related
information (e.g. cookies). This leads to the below convention when an option
for different languages is required.

*All* available languages should come as different DNS records, pointing to the
same host, in the format `<language_code>`.`<host>`

For example, for the english site of internet.nl it would be: `en.internet.nl`

The available languages should also be included as LANGUAGES in django's
settings.py file.

The default language's (configured via django's settings.py file) prefix is
ommited from the hostname by default.
