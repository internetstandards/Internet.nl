# Docker / Docker Compose / Getting Started

This documented is intended as a quick simple guide to setup a development environment or run the integration test environment. For more detailed information refer to the [Development Environment](Docker-development-environment.md) or [Integration tests](Docker-integration-tests.md) files.

## Prerequisites

An OCI compatible container runtime with [Compose V2](https://docs.docker.com/compose/migrate/) is required to run the project. For example one of the following:

- [Docker](https://docs.docker.com/get-docker/) for Linux, (supported, tested version 24.0.2)
- [Docker](https://docs.docker.com/get-docker/) for Mac (supported, tested version 4.21.0)
- [Colima](https://github.com/abiosoft/colima) for Mac (recommended, tested version 0.5.5)
- [Docker](https://docs.docker.com/get-docker/) for Windows (untested)

**notice**: your Docker runtime should be configured with enough memory and CPU, otherwise the environment will be unstable. Minimum is at least 4GB memory and 2 CPU cores, more is better for quicker rebuild/restart of images/containers.

## Building

Clone this repository to a local directory:

    git clone https://github.com/internetstandards/Internet.nl/ --branch docker
    cd Internet.nl

Then make sure all Git Submodules are checked out and up to date with the following command:

    GIT_LFS_SKIP_SMUDGE=1 git submodule update --init

Build the Docker images for the application and development (testing, dev-tools, etc):

    make build

This will take a few minutes to complete.

## Different environments

There are 2 environment for development, the "development" and "integration test" environment. Both can be used for development but there are some differences in how they handle certain things. Please see the table below:

|                     | Development               | Integration test           |
|---------------------|---------------------------|----------------------------|
| Focus               | Ease/speed of development | Consistency, prod-parity   |
| Networking          | Public internet           | Isolated internal          |
| Internet connection | Yes                       | No                         |
| IPv6                | Native (tunneled) IPv6    | Private IPv6 network       |
| DEBUG mode          | On                        | Off                        |
| Debug logging       | On                        | On                         |
| Server              | Django runserver          | uWSGI                      |
| Python source files | Mounted                   | from build image           |
| Website             | http://localhost:8080     | http://localhost:8081      |
| Autoreload          | `.py` files               | No                         |
| Tests               | Yes                       | Yes                        |

Both environment can be setup and run at the same time without conflict. Depending on the kind of work you wish to perform one environment might be better suited that the other.

## Development environment

The development environment runs the full application stack with debugging on and allows testing against targets on the internet.

To start the development environment use the following command:

    make up env=develop

The command will wait for the stack to come up completely and be in a healthy state. This might take a minute or 3. After which the application is accesible on the address: http://localhost:8080. Logs can be streamed using:

    make logs env=develop

A very basic test suite is available for the development environment to verify its functionality. It is not as complete as the one in the integration test environment. To run the testsuite use:

    make develop-tests env=develop

Please be aware some features don't work out of the box due to limitations of the environment. IPv6 connectivity is not available. RPKI tests rely on Routinator syncing up from external databases and will take a while (`docker logs internetnl-routinator-1 -f`). Connection test will not work because it requires external connectivity and DNS records to be setup.

The development environment uses volume mounts and automatically picks up changes on Python source files for the `app`, `worker` and `beat` container. For any other change you need to run `make build` and `make up`.

To stop the running stack use:

    make stop env=develop

This will keep transient data (databases, etc). The stack can be brought up again with: `make up`.

To completely stop and remove all data from the instance run:

    make down-remove-volumes env=develop

Please refer to [Development Environment](Docker-development-environment.md) for further reading.

## Integration test environment

The integration test suite runs the full application stack and additional components (internal resolver, mock target, test-runner, etc) required for testing. It is a separate environment from the development environment and runs isolated without internet connection. It has an internal IPv6 network. This environment matches the Github Actions CI and production deployments the closest.

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

Please refer to [Development Environment](Docker-development-environment.md) for generic information about the development environment and [Integration tests](Docker-integration-tests.md) for further reading specific to the Integration test environment.

## Live tests

Besides the integration tests suite there is also the Live tests suite. This suite is similar to the integration tests but runs against deployed instances running locally or on the internet. It is less intended as a development aid and more as a smoketest to verify if a deployed installation is working as expected.

To run the live test suite use the following command:

    make live-tests

This will run against the `https://internet.nl` instance, to specify a different instance run:

    APP_URLS=https://example.com make live-tests

By default some tests will be skipped, for example due to limitations of the environment (missing IPv6), or required information (eg: Batch API authentication).

It is also possible to run the live tests suite without checkout out the source and building the test image, for this run:

    docker pull ghcr.io/internetstandards/test-runner && docker run -ti --rm --env=APP_URLS=https://example.com ghcr.io/internetstandards/test-runner

Please refer to [Live tests](Docker-live-tests.md) for more information about live tests.

### Test all

To run build and all checks and test suites in one go, use:

    make test-all

## References

- https://docs.docker.com/compose/compose-file/
- https://github.com/compose-spec/compose-spec/blob/master/spec.md
- https://docs.docker.com/compose/extends/