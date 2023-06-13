# Docker Integration Tests



**notice**: depending on the Docker runtime it might take a moment for changes made to a file to synchonize into the running containers.

### IPv6

    export IPV6_SUBNET_LIVE_TESTS=2a01:4f9:c010:dd7b:10::/80
    export IPV6_GATEWAY_LIVE_TESTS=2a01:4f9:c010:dd7b:10::1
    export IPV4_SUBNET_PUBLIC=172.44.0.0/16
    export APP_URLS=https://internet.nl,https://locohost.nl
    export TEST_DOMAINS=internet.nl,locohost.nl
    make live-tests-ipv6 testargs=-kwebsite

### Debugging tests

#### Local

##### Test screenshot/video/logs

On test failure a video, screenshot, trace and log output regarding the failed test are placed in the `test-results/<test-name>` folder in the project source.

##### RabbitMQ queues

RabbitMQ Web admin interface is exposed, even in the isolated integration test environment. If queue introspection is needed browse to http://guest:guest@localhost:15672/.

#### CI (Github Actions)
On test failure a video, screenshot, trace and log output regarding the failed test are generated. These can be downloaded as artifacts after the entire testrun has completed on the 'Summary' page of the Action Run: `https://github.com/internetstandards/Internet.nl/actions/runs/<run-id>`.

#### Trace view

Besides screenshot and video it is also to generate debug information in a `trace.zip` file for each failed test. The trace file contains a complete debug trace with JS console output and network graph. To generate the trace file run the integration tests with `make integration-tests-trace`. To view the trace please refer to https://playwright.dev/python/docs/trace-viewer.

### Tips and tricks

#### Focussing on single tests

The testsuite uses Pytest underneath. Which allows for many options to narrow down the testsuite en quickly run a smaller subset of tests. Arguments to Pytest are passed through `testargs=`.

Make Pytest exit on the first failing test:

    make integration-test testargs=-x

Select a specific test by matching the name:

    make integration-test testargs=-kbatch

Run the last failed tests first, then continue with the rest of the suite:

    make integration-test testargs=--ff

Run only the last failed tests:

    make integration-test testargs=--lf

Run test from newer files first:

    make integration-test testargs=--nf

Get a list of all tests:

    make integration-test testargs=--collect-only

Multiple arguments can be combined but must be quoted:

    make integration-test testargs="-x --ff"

Get Pytest help:

    make integration-test testargs=--help