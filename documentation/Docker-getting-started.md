# Docker / Docker Compose / Getting Started

This documented is intended as a quick simple guide to setup a development environment or run an integration test. For more detailed information refer to the [Development Environment](documentation/Docker-development-environment.md) or [Integration tests](documentation/Docker-integration-tests.md) files.

## Prerequisites

An OCI compatible container runtime with [Compose V2](https://docs.docker.com/compose/compose-file/compose-file-v2/) is required to run the project. For example one of the following:

- [Docker](https://docs.docker.com/get-docker/) for Linux, (supported)
- [Docker](https://docs.docker.com/get-docker/) for Mac (supported)
- [Colima](https://github.com/abiosoft/colima) for Mac (recommended)
- [Docker](https://docs.docker.com/get-docker/) for Windows (untested)

## Building

After cloning this repository locally make sure all Git Submodules are checked out and up to date with the following command:

    git submodule update --init

First build the Docker images for the application using the following command:

    make docker-compose-build

## Development environment

The development environment runs the full application stack and allows testing against targets on the internet.

To start the development environment use the following command:

    make docker-compose-up

The command will wait for the stack to come up completely and be in a healthy state. After which the application is accesible on the address: http://localhost:8080. Logs can be streamed using:

    make docker-compose-logs

Please be aware some features don't work out of the box due to limitations of the environment. IPv6 connectivity is not available. RPKI tests rely on Routinator syncing up from external databases and will take a while (`docker logs internetnl-routinator-1 -f`). Connection test will not work because it requires external connectivity and DNS records to be setup.

To stop the running stack use:

    make docker-compose-stop

This will keep transient data (databases, etc). The stack can be brought up again with: `make docker-compose-up`.

To completely stop and remove all data from the instance run:

    make docker-compose-down-remove-volumes

Please refer to [Development Environment](documentation/Docker-development-environment.md) for further reading.

## Integration tests

The integration test suite runs the full application stack and additional components (internal resolver, mock target, test-runner, etc) required for testing. It is a separate environment from the development environment and runs isolated without internet connection to ensure test consistency. It has an internal IPv6 network.

To bring up the test environment and run the test suite use the following command:

    make integration-tests environment=test

This command will wait for the stack to come up completely and be in a healthy state, after which the testsuite will begin to run.

Though the environment is isolated it is possible to visit the app at the address: http://localhost:8081. Targets on the internet will not be available for testing, instead use the mock targets, eg: https://target.test.

The test environment will remain running after the test, to stop the running stack use:

    make docker-compose-stop environment=test

To completely stop and remove all data from the instance run:

    make docker-compose-down-remove-volumes environment=test

Please refer to [Integration tests](documentation/Docker-integration-tests.md) for further reading.

## References

- https://docs.docker.com/compose/compose-file/
- https://github.com/compose-spec/compose-spec/blob/master/spec.md
- https://docs.docker.com/compose/extends/