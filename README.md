# Internet.nl

Internet.nl is an initiative of the Dutch Internet Standards Platform that
helps you to check whether your website, email and internet connection use
modern and reliable Internet Standards. And if they don’t, what can you do
about it?


## Background

With the test tool Internet.nl users can easily check whether their internet is
'up to date' i.e. if their website, email and internet connection use modern
internet standards. The tool provides detailed background information on the
test results with (pointers to) how-to's and manuals.

The test tool Internet.nl is an initiative of the Dutch Internet Standards
Platform which is a collaboration of partners from the internet community and
the Dutch government. The platform's mission is to jointly promote the use of
modern internet standards keeping the internet reliable and accessible for
everybody. [ECP](https://ecp.nl/) provides for the administrative home of the
platform. [NLnet Labs](https://nlnetlabs.nl/) laid the foundation for 
Internet.nl and the underlying tooling. 

From 1 April 2021 onwards, maintenance and further development will be carried
out by the project team of the Internet Standards Platform.


## Scope

Currently the following modern internet standards are considered within scope:
  - IPv6 (modern address),
  - DNSSEC (signed domain),
  - HTTPS (secure website connection),
  - website security options (such as security headers),
  - STARTTLS and DANE (secure mail server connection),
  - DMARC+DKIM+SPF (anti-spoofing), and
  - RPKI (secure routing).

Web standards (such as HTML) or identity standards (like SAML or OpenID
Connect) are out of scope.

Although many of the tested internet standards contribute to a higher security
level of your website, mail service or internet connection, a 100% score does
not mean that an online service is fully secure. There are more aspects which
are important for the security of your online services. But these are out of
scope for Internet.nl. Please keep in mind that Internet.nl is foremost
intended as an internet standards compliance test and not as a security test.


## Getting started

Note: the docker image will not build at the moment, this is a work in progress and will be in 1.4.1.

Internet.nl is a [Django](https://www.djangoproject.com/)
based application.

Current install base is Django 3.2 with Python 3.7.


### Quick start

Although the first open source release of the project is aimed to provide
transparency on the tool and the way the tests are run, there is (currently) no
trivial way to install the software. Nonetheless, you could easily spin up a
ready to use local dockerized environment for local development and testing
purposes by following the [docker instructions](https://github.com/internetstandards/Internet.nl/blob/master/docker/README.md).


### Dev start
Currently x86_64 only. So m1 mac users should `arch -x86_64 /bin/sh` before continuing (the makefile does that too).

Install the required system requirements from the [installation instructions](https://github.com/internetstandards/Internet.nl/blob/master/documentation/Installation.md).

```bash
git clone https://github.com/internetstandards/Internet.nl/
cd Internet.nl
make venv

# Install separate dependencies, for which no wheels are available:
# Note that unbound comes in a variety of flavors in the makefile(!)
make unbound
make python-whois
make nassl

# Run the application, and the workers
make run
make run-worker
make run-heartbeat
```

Running tests is not yet streamlined, it requires a test worker to be ran.
```bash
make run-testworker
make test
```


### Slow start

If you feel brave enough for a system install you can follow the
[installation instructions](https://github.com/internetstandards/Internet.nl/blob/master/documentation/Installation.md).

The [customize instructions](https://github.com/internetstandards/Internet.nl/blob/master/documentation/Customize.md) describe how you could
customize your installation.

The [deployment instructions](https://github.com/internetstandards/Internet.nl/blob/master/documentation/Deployment.md) provide information
relevant to the deployment of your installation and steps you need to run
before starting/updating your installation.

Example configuration files for the internet.nl ecosystem can be found
[here](https://github.com/internetstandards/Internet.nl/blob/master/documentation/example_configuration).


## Building blocks

Internet.nl was made possible by using and combining other open source software.
The main open source building blocks of Internet.nl are:

- [Python 3](https://www.python.org/) (main programming language)
- [Django](https://www.djangoproject.com/) (web framework)
- [PostgreSQL](https://www.postgresql.org/) (database)
- [Celery](http://www.celeryproject.org/) (asynchronous tasks backend)
- [Redis](https://redis.io/) (cache backend for Django and Celery)
- [RabbitMQ](https://www.rabbitmq.com/) (message broker for Celery)
- [nassl](https://github.com/nabla-c0d3/nassl) (Python bindings for OpenSSL)
- [unbound/libunbound](https://www.nlnetlabs.nl/projects/unbound/about/) (DNS related tests and functionality)
- [Postfix](https://www.postfix.org/) (mail server for interactive email test, _beta_)


## Contributing

We are happy to receive pull requests but keep in mind the scope of the
project. Before starting work on something that you are not sure if it falls
under the scope it is advised to first file an issue and start a discussion on
the matter.


## License

This project is licensed under the Apache License, Version 2.0 - see the
[LICENSE-Apache-2.0.txt](LICENSE-Apache-2.0.txt) file for details.

The files under the `/translations` folder are licensed under Attribution 4.0
International (CC BY 4.0) - see the [LICENSE-CC-BY-4.0.txt](LICENSE-CC-BY-4.0.txt)
file for details.

### Name and logo
Both the name Internet.nl and the Internet.nl logo are explicitly excluded from
the above licensing. Thus we do not grant permission to use these when our
content or software code is reused.
