# Installation

Internet.nl is a [Django](https://www.djangoproject.com/)
based application and therefore inherits its requirements.

Current install base is Django 3.2 LTS with Python 3.7.

Note that previous installation instructions have been moved to a makefile. This prevents a lot of copy pasting of commands.

The following instructions should work on most Debian-based systems. Tested on Ubuntu 18.04
Example configuration files for the internet.nl ecosystem can be found
[here](https://github.com/internetstandards/Internet.nl/blob/master/documentation/example_configuration).

## System requirements

Install the following system requirements:

`apt install git git-lfs python3 python3-pip build-essential libssl-dev libffi-dev python-dev postgresql postgresql-server-dev-all swig libevent-dev libhiredis-dev redis-server rabbitmq-server bison python3-venv`

## Software

### Python 3

Create a virtual environment with: 
`make venv`

### nassl

Install with:
`make nassl`

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
`make unbound-3.7`

Unbound (and pylibunbound) is used as a DNS resolver/nameserver for the various
tests performed.

Use the fork at https://github.com/internetstandards/unbound.git
Make sure to use the `internetnl` branch and follow the
[README.md](https://github.com/internetstandards/unbound/blob/internetnl/README.md)
instructions for installation.

Note: before compiling unbound you also need to edit the DNS labels for your
connection test domain.

If you setup a python virtual environment you should enable it for unbound's
installation.

For the connection test, [specific DNS records are needed](https://github.com/internetstandards/unbound/blob/internetnl/README.md#configuration).

Manually running unbound can be done with `unbound -d -vvvv`. This opens unbound in a console with maximum debug logging.
This helps figuring out if everything is set up properly. Unbound will use syslog after starting, and you'll need to
look in the system log for unbound. On mac os you can use the console.app to filter on unbound and see errors there.

You can verify unbound running by:

```
dig internet.nl @localhost
```
When not running the query will hang or say "@localhost" not found.

When running it should give an answer like this:
```
; <<>> DiG 9.10.6 <<>> internet.nl @localhost
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 32270
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;internet.nl.			IN	A

;; ANSWER SECTION:
internet.nl.		3054	IN	A	62.204.66.10

;; Query time: 24 msec
;; SERVER: ::1#53(::1)
;; WHEN: Wed Jan 19 16:02:18 CET 2022
;; MSG SIZE  rcvd: 56
```

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


### Routinator

[Routinator](https://www.nlnetlabs.nl/projects/rpki/routinator/) is used for
[RPKI validation](rpki.md).
There are some publicly available instances that can be used for local
testing, like `https://rpki-validator.ripe.net/api/v1/validity`, but large
scale or production setups, you should run your own instance.

* For installation you can follow [the manual](https://routinator.docs.nlnetlabs.nl/en/stable/installation.html).
* Note that Internet.nl uses the local HTTP API, by default on port 9956,
  not the RTR(TR) protocol. For at least docker, port 9556 is not available
  by default with the commands in the manual - you need to add `-p 9556:9556`
  to the Docker command. In some packages, this same interface is hosted
  on port 8323 instead. You can verify with just a basic HTTP request.
* The `ROUTINATOR_URL` setting must have the full path to the validity API,
  which usually is the same, e.g. `"http://localhost:9556/api/v1/validity"`.
  (Note that the normal response on this URL is "Not found".)
* Routinator will take some time to initialise. The same HTTP interface as
  the API will show the current status.


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
* service internetnl-batch-celery-workers restart
* service internetnl-batch-celery-scheduler restart
* service internetnl-batch-celery-heartbeat restart
* service internetnl-gunicorn restart
* service internetnl-unbound restart
 
If things don't happen, you can inspect the current queues with:
`rabbitmqctl list_queues`

And you can see what workers are running in memory with:
`ps aux | grep python`

Restart all internetnl services:
* `for i in $(ls -1 /etc/systemd/system/internetnl-*.service); do systemctl restart `basename $i`; done`

Restart all batch workers:
* `for i in $(ls -1 /etc/systemd/system/internetnl-batch*.service); do systemctl restart `basename $i`; done`


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
