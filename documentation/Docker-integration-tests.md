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
On test failure a video, screenshot, trace and log output regarding the failed test are placed in the `test-results/<test-name>` folder in the project source.

#### CI (Github Actions)
On test failure a video, screenshot, trace and log output regarding the failed test are generated. These can be downloaded as artifacts after the entire testrun has completed on the 'Summary' page of the Action Run: `https://github.com/internetstandards/Internet.nl/actions/runs/<run-id>`.

#### Trace view

Besides screenshot and video it is also to generate debug information in a `trace.zip` file for each failed test. The trace file contains a complete debug trace with JS console output and network graph. To generate the trace file run the integration tests with `make integration-tests-trace`. To view the trace please refer to https://playwright.dev/python/docs/trace-viewer.