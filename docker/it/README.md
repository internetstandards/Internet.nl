# Internet.NL Docker & Selenium based integration test framework

This directory contains everything needed to build and deploy the environment
required by the tests located in the ../../tests/it/ directory.


## Quick start

### Running the automated integration test suite

```
$ ./travis-like.sh
```

### Running a subset of the automated integration test suite

```
$ export TEST_SELECTOR=tls12  # for example, only TLS 1.2 tests
$ ./travis-like.sh
```

### Browsing the Internet.nl website in the integration test environment

```
$ export TEST_SELECTOR=NoTestsPlease
$ docker-compose up --build -V
```

## Full documentation

### What is this?

Welcome to an integration test suite for the Internet.NL application that can
be used to test the behaviour of the Internet.NL application against a
collection of "mock" test servers which demonstrate weak properties that the
Internet.NL application is supposed to detect and warn about in the reports
that it generates.

### How do I use it?

Run Docker Compose, wait for the tests to run, then browse the generated HTML
report. Alternatively leave the application deployed and interact with it
manually via your browser.

### Requirements

To run the integration test suite you will need Docker and Docker Compose
installed locally on your computer and a git clone copy of the Internet.NL
source code including the integration test framework and tests.

> See the appendices for details on versions known to work.

Links:
- https://docs.docker.com/install/linux/docker-ce/ubuntu/#install-docker-ce
- https://docs.docker.com/compose/install/


### Running the automated integration test suite

Run the following commands (assumes that you have Docker and Docker-Compose
installed and that your local Docker Daemon has been configured to support
IPv6).

```
$ cd docker/it      # the directory containing this file
$ ./travis-like.sh
```

This will:

1. (Re)build any missing/modified/impacted Docker images.
2. Create the test environment locally on your computer as a collection of
   Docker containers.
2. Run the Python based tests in ../../tests/it/.
3. Capture the results to /tmp/it-report/ on your computer.
4. Tear the created environment down.

As you can see from the name, the intention is to integrate this in future with
Travis CI.


### Browsing the Internet.nl website in the integration test environment

Run the following commands (assumes that you have Docker and Docker-Compose
installed and that your local Docker Daemon has been configured to support
IPv6).

```
$ cd docker/it      # the directory containing this file
$ export TEST_SELECTOR=NoTestsPlease
$ docker-compose up --build -V
```

This will:

1. (Re)build any missing/modified/impacted Docker images.
2. Create the test environment locally on your computer as a collection of
   Docker containers.
2. Prevent the execution of any automated tests.

You can now browse locally on your computer to the Internet.NL app inside the
docker integration test network:

   http://localhost:8080/

You can now test a domain such as tls10only.test.nlnetlabs.tk.
See docker/it/dns/submaster/nsd/test.nlnetlabs.tk for other subdomains that
you can test.

> **NOTE:** you can test some real FQDNs but _only for TLDs that are forwarded_
> in `docker/it/dns/resolver/unbound/unbound.conf`. Testing such domains will
> fail DNSSEC validation because the root anchor used to signed the DNS
> hierarchy will be the real DNSSEC internet root anchor, not the fake DNSSEC
> root anchor installed on the integration test framework fake root server.



## Appendices

### Appendix: Integration test execution sequence
```
=========================  DOCKER CONTAINERS/GROUPS   =========================
testrunner    internetnl    selenium    selenium-firefox    dns        target
              tests  app      hub         instances     hierarchy     servers
==============================================================================
      |
      | 1) sign DNS zones
      |------------------------------------------------>|
      |
      | 2) install DNS root anchor
      |-------------->|
      |               | unblocks launch of the Internet.NL 'app'
      |
      | 3) run tests using docker exec pytest
      |-------->|
      |         | browse the Internet.NL website
      |         |------------->|------------>|
      |         |              |             |-------------->|
      |         |              |             |<--------------|
      |         |     |<-------|-------------|
      |         |     |
      |         |     | exercises the Internet.NL app and the target servers
      |         |     |-->:
      |         |     |   :--------------------------------->|
      |         |     |   :<---------------------------------|
      |         |     |   :
      |         |     |   :--------------------------------------------->|
      |         |     |   :<---------------------------------------------|
      |         |     |<--v
      |
      | 4) write results to host via Docker mount
<-----|
===============================================================================
```


### Appendix: High level network & deployment architecture
```
             --- PRIVATE DOCKER NETWORK ---------------------------------------
             | 172.16.238.0/24 2001:3200:3200::/64                            |
             |                                                                |
             |    -----------------   ----------                              |
  8.8.8.8    |    | DNS root, TLD |   | CA &   |                              |
(forwarded<-------- & authority   |   | OCSP   |                              |
 zones only) |    | servers       |   | server |                              |
             |    -----------------   ----------                              |
             |                                                                |
             |    ----------------    -------------------                     |
             |    | Internet.NL  |    | Redis, RabbitMQ |                     |
    :8080 o-------- Django Debug |    | & PostgreSQ L   |                     |
             |    | HTTP server  |    | servers         |                     |
             |    ----------------    -------------------                     |
             |                                                                |
             |    ------------------  ----------------------                  |
             |    | Target HTTP(S) |  | Target SMTP (+TLS) |                  |
             |    | servers        |  | servers            |                  |
             |    ------------------  ----------------------                  |
             |                                                                |
             |    ---------------     ----------------    ----------------    |
             |    | Test runner |     | Selenium Hub |    | Selenium web |    |
             |    | server      |     | server       |    | browser grid |    |
             |    ---------------     |--------------|    ----------------    |
             |                                                                |
             ------------------------------------------------------------------
```


### Appendix: Supported versions and configuration
```
$ cat /etc/lsb-release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=19.04
DISTRIB_CODENAME=disco
DISTRIB_DESCRIPTION="Ubuntu 19.04"

$ docker version
Client:
 Version:           18.09.5
 API version:       1.39
 Go version:        go1.10.8
 Git commit:        e8ff056
 Built:             Thu Apr 11 04:44:15 2019
 OS/Arch:           linux/amd64
 Experimental:      false

Server: Docker Engine - Community
 Engine:
  Version:          18.09.5
  API version:      1.39 (minimum version 1.12)
  Go version:       go1.10.8
  Git commit:       e8ff056
  Built:            Thu Apr 11 04:10:53 2019
  OS/Arch:          linux/amd64
  Experimental:     false

$ docker-compose version
docker-compose version 1.24.0, build 0aa59064
docker-py version: 3.7.2
CPython version: 3.6.8
OpenSSL version: OpenSSL 1.1.0j  20 Nov 2018

$ cat /etc/docker/daemon.json
{
	"ipv6": true,
	"fixed-cidr-v6": "2001:3984:3989::/64"
}
```



### Appendix: Deploying in Digital Ocean
Links:
  - https://docs.docker.com/machine/install-machine/
  - https://github.com/digitalocean/doctl
  - https://cloud.digitalocean.com

```
export DIGITALOCEAN_ACCESS_TOKEN=<YOUR API KEY>

# the doctl command can be useful for determining values to pass to docker-machine:
# doctl compute region ls
# doctl compute size ls
# doctl compute image list-distribution

docker-machine create \
    --driver digitalocean \
    --digitalocean-region ams3 \
    --digitalocean-ipv6 \
    --digitalocean-image ubuntu-18-04-x64 \
    --digitalocean-size g-4vcpu-16gb \
    --digitalocean-tags SOME,TAGS \
    YOURMACHINENAME

eval $(docker-machine env YOURMACHINENAME)

cd <internetnl src dir>docker/it
docker-compose up --build -d
```


### Appendix: Connecting to the database
```
docker-compose exec postgres psql -U internetnl internetnl_db
```
