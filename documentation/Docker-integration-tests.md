# Docker Integration Tests

The Integration test environment provides a way to bring up the full Internet.nl application stack using Docker Compose. The environment runs in an isolated network with private IPv4 and IPv6 subnets and its own DNS resolver. This to ensure the integration test suite runs consistent and without outside influence across multiple environments (eg: developer workstation, Github Actions CI). This means that it is not possible to test against targets on The Internet using the integration test environment.

A lot of information in [Development Environment](Docker-development-environment.md) documentation also applies to the Integration test environment in terms of debugging and troubleshooting commands.

## Overview

For the application stack the information in [Development Environment#Overview](Docker-development-environment.md#Overview) applies as well.

Additionally this environment also contains a test runner, test targets and it's own resolver.

Even though the network is isolated, as a developer you connect to the application through `http://localhost:8081/`. This will take you through the `port-expose` and the `webserver` to the application.

### Test runner

Test are run by the `test-runner` which spawns as a container inside the isolated network. The test runner runs tests from the `integration_tests/integration/` directory. Test are run using a built-in headless browser (default: Chrome, available: Firefox, Webkit) controlled by [Playwright](https://playwright.dev/python/) or directly using the Requests library (eg: for Batch tests). The browser tests allow for testing the full stack including HTML, CSS and JavaScript components of the application.

### Internal resolver

All IP addresses used in the isolated network are in private address ranges (`172.16.43.0/24`, `fd00:43:1::/64`) and all domain names use the `.test` domain. The internal `resolver` runs dnsmasq to provide routing of the internal domain and stub records for external services (eg: Cymru origin ASN query). The resolver configuration file is `docker/integration-tests/dnsmasq/entrypoint.sh`.

During integration test runs the environment variable `INTEGRATION_TESTS` is set to `True` which makes the application's Unbound resolver use the internal resolver, and allows resolving of the `.test` TLD.

### The test targets

There are two test targets used in the integration tests. For HTTP tests `target.test` and for e-mail `mx.target.test`. When testing through the web interface these can be used as well.

The HTTP test target container runs a Nginx instance which can be configured for different scenarios that might be tested. The configuration file for this is located at: `docker/integration-tests/nginx_templates/test-target.conf.template`.

The e-mail target run a mock mailserver and is configured in the `docker/compose.integration-tests.yaml` file.

### PKI/self-signed certificate

The integration test environment uses a self-signed CA to generate TLS certificates for internal use. The expiration of this CA is set to 5 years.

Configuration of the CA and generation of certificates is done in `docker/integration-tests/pki`.

To regenerate the CA and all certificates run:

    cd docker/integration-tests/pki && make clean all

Below is an overview of all parts of the integration test environment and their interconnection:

![integration test environment container overview](images/integration_test_environment.png)

## Setup

For requirements and setup of the development environment please first refer to the [Getting started](Docker-getting-started.md) document.

## Running tests

The integration test suite runs the full application stack and additional components (internal resolver, mock target, test-runner, etc) required for testing. It is a separate environment from the development environment and runs isolated without internet connection to ensure test consistency. It has an internal IPv6 network.

To bring up the test environment and run the test suite use the following command:

    make up env=test
    make integration-tests env=test

This command will wait for the stack to come up completely and be in a healthy state, after which the testsuite will begin to run. The environment can also be brought up without running tests using: `make up env=test`.

Though the environment is isolated it is possible to visit the app at the address: http://localhost:8081. Targets on the internet will not be available for testing, instead use the mock targets, eg: https://target.test.

For changes in any files to take effect you need to rebuild and update the required containers using the commands `make build env=test` and `make up env=test`.

The test environment will remain running after the test, to stop the running stack use:

    make stop env=test

To completely stop and remove all data from the instance run:

    make down-remove-volumes env=test

## Debugging/introspection/troubleshooting/resettings

A lot of the information in [Development Environment#debuggingintrospectiontroubleshootingresettings](Docker-development-environment.md#debuggingintrospectiontroubleshootingresettings) applies to the integration test environment as well.

**notice**: for the integration test environment the `make` commands must include the `env=test` argument to execute against the correct environment!

### Browser test screenshots/videos/logs/network graphs

Because the Playwright browser tests run in a headless container it is not possible the view the browser window during the test. However the browser will collect a screenshot, video and logs/network graphs from the debugger and export them on test failure.

When running on your workstation these files are places in the `test-results/<test-name>` directory.

Trace logs can sometimes cause tests to fail if the entire testsuite is run. That's why they are not enabled by default. To run the test suite with tracing on use: `make integration-tests-trace`.

The trace logs are stored in a `trace.zip` file for each failed test. For more information on viewing trace logs refer to: https://playwright.dev/python/docs/trace-viewer.

Or simple upload the `trace.zip` to the online viewer: https://trace.playwright.dev

In the Github Actions CI environment these are also captured and stores as artifacts, these can be downloaded after the entire testrun has ended on the 'Summary' page of the Action Run: `https://github.com/internetstandards/Internet.nl/actions/runs/<run-id>`.

### RabbitMQ queues

RabbitMQ Web admin interface is exposed, even in the isolated integration test environment. If queue introspection is needed browse to http://guest:guest@localhost:15673/.

### Web interface

The web interface of the application can be visited at: http://localhost:8081.

### Interacting from the test-runner perspective

It is possible to open a shell inside a test runner container to interact with the integration test environment the same way the test suite would. Do this by running the command:

    make test-runner-shell

After which you can interact with the application with for example curl:

    curl -kI https://internet.test

Or with the test target:

    curl -kI https://target.test

### Git bisect using testsuite

Sometime it's hard to pin down why tests broke. Especially if you have many commits in between a successful integration test run and a failed one. Git offers a tool to quickly hunt down the one commit that broke the build. Using the integration test suite as a validation command do the following:

    git bisect start
    git bisect good <SHA/branch/tag of good commit>
    git bisect bad <SHA/branch/tag of bad commit>
    git bisect run make build integration-test
    git bisect reset

This should now lead to Git narrowing down from the good and bad commit to the one that broke the build.

For more information also see: https://git-scm.com/docs/git-bisect

## Tips and tricks

### Focussing on tests

The testsuite uses Pytest underneath. Which allows for many options to narrow down the testsuite en quickly run a smaller subset of tests. Arguments to Pytest are passed through `test_args=`.

Make Pytest exit on the first failing test:

    make integration-tests test_args=-x

Select a specific test by matching the name:

    make integration-tests test_args=-kbatch

Run the last failed tests first, then continue with the rest of the suite:

    make integration-tests test_args=--ff

Run only the last failed tests:

    make integration-tests test_args=--lf

Run test from newer files first:

    make integration-tests test_args=--nf

Get a list of all tests:

    make integration-tests test_args=--collect-only

Multiple arguments can be combined but must be quoted:

    make integration-tests test_args="-x --ff"

Get Pytest help:

    make integration-tests test_args=--help

### Rebuilding test runner image

Changes to the `test-runner.Dockerfile` file (for example when upgrading Playwright) are not automatically picked up. To force a rebuild of the `test-runner` image delete the current image:

    docker image rm ghcr.io/internetstandards/test-runner