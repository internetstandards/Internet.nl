# internet.nl architecture

_This document is a work in progress_


## Building blocks

Fundamental open source building blocks are:

- [Python 3](https://www.python.org/) (main programming language)
- [Django](https://www.djangoproject.com/) (web framework)
- [PostgreSQL](https://www.postgresql.org/) (database)
- [Celery](http://www.celeryproject.org/) (asynchronous tasks backend)
- [Redis](https://redis.io/) (cache backend for Django and Celery)
- [RabbitMQ](https://www.rabbitmq.com/) (message broker for Celery)
- [nassl](https://github.com/nabla-c0d3/nassl) (Python bindings for OpenSSL)
- [unbound/libunbound](https://www.nlnetlabs.nl/projects/unbound/about/) (DNS related tests and functionality)


## Overview

![](inl-architecture.png)

This internet.nl codebase is a Python/Django project, though most complexity is
in the checks which are not Django specific. The checks are run as Celery jobs,
using Redis and RabbitMQ for messaging and results. While running a test,
the user's browser makes periodic calls to see whether results are ready.
Essentially, this part is a fairly ordinary Django application with background
jobs.

The checks can be split in inbound (connection test) and outbound (web, mail):

* Outbound checks: the test is performed by making outbound connections for
  DNS, TLS and HTTP(S). The code needs IPv4 and IPv6 connectivity, a DNS resolver,
  our custom nassl, and a standard `ldns-dane`.
* Inbound checks: the test is performed by getting the browser to make various
  HTTP requests to check connectivity. This requires a custom unbound install
  serving specific zones, and a more complex webserver config.

The checks can also be triggered in different ways:

* Interactive mode through the regular website, at a user's request.
* [Batch mode](Batch.md) through API calls or by scheduling through the
  dashboard. Only outbound checks are possible in this method.


## Task management

There are up to three types of Celery processes running:

* The workers that perform the actual tests.
* A [celery beat](https://docs.celeryq.dev/en/stable/userguide/periodic-tasks.html)
  to update the Hall of Fame on interactive instances and
  perform other periodic tasks. (May have a role in scheduling batch?)

The workers use several queues, which can be found in the
[example configuration](https://github.com/internetstandards/Internet.nl/tree/main/documentation/example_configuration/opt_internetnl_etc)
These prevent a single slow job from holding up all others. The grouping of
tasks into queues is not entirely structured well.


## Web server

The web server is an Apache and gunicorn setup, with some special
configuration. See the example configuration for details, but this
comes down to:

* For single outbound web/mail tests, no special configuration is needed.
* For the connection test, a number of alternative hostnames need to
  be configured, some without HTTPS redirect. For example, the connection
  test verifies direct IPv6 connections, for which there is no TLS
  certificate.
* For a batch host, access is limited to test results and only after HTTP
  basic auth. This is used to allow dashboard users (which uses API calls)
  to see detailed test results.


## Unbound

The project needs a
[custom build of Unbound](https://github.com/internetstandards/unbound)
for the connection test. For other tests, a regular Unbound will suffice,
but we tend to use the same custom version.

The custom change is an extra module that saves certain info in Redis, if
it detects queries for the connection test (sub)domain. This allows the
connection test to report on the user's resolver. It also has code for
an interactive email test for the future.

The connection test also needs a few specific zones, documented in the README
of that repository. 


## Other parts

* Other than Celery results, Redis is also used as a regular cache: it keeps
  info on MAC addresses (for the IPv6 privacy extensions test), and the stats
  displayed on the front page.
