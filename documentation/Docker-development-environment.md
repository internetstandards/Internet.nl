# Docker Development Environment

## Overview

TODO: explain how the development environment is setup, moving components, docker, etc

![network diagram](images/development-environment.png)

## Setup

For requirements and setup of the development environment please refer to the [Getting started](documentation/Docker-getting-started.md) document.

    git clone https://github.com/internetstandards/Internet.nl/ --branch docker
    GIT_LFS_SKIP_SMUDGE=1 git submodule update --init
    make docker-compose-build
    make docker-compose-up

## Development cycle

There are multiple to iterate over changes and rebuilding/restarting the development environment depending on what kind of changes are made. Some will be quicker than others because not everything is rebuild. Others are more complete/safe as they rebuild everything but might be a little slower.

### Rebuild/restart containers

The default way of rebuilding/restarting everything after a code change is to run the following two commands:

    make docker-compose-build
    make docker-compose-up

This will first rebuild all container images that need rebuilding. Layer caching is leveraged to provide the quickest possible way to rebuild the images and skipping steps that are not needed. But when for example the requirements.txt file or a vendored source changes most of the container will be rebuild, which takes some time.

After rebuilding the images all containers who's image has changed will be restarted with the new image.

These commands can be combined into one like so:

    make docker-compose-build docker-compose-up

It is possible to limit the build and up actions to specific services. So only the containers for those services are rebuild/restarted. To do this provide the `services=` argument like so:

    make docker-compose-build docker-compose-up services=app

Multiple services can be specified:

    make docker-compose-build docker-compose-up services="app worker"

### Using source bind volumes

Most changes to only the Python source do not require the rebuilding of images, when you don't need to change any of the following:

- template/translations/staticfile/js/css
- requirements.txt files
- sources in `vendor/`
- Dockerfile/docker-compose.yml files

It is possible to bind mount parts of the Python source code into the container as volumes. This way changes can be quickly iterated over by just restarting the container.

TODO: or using autoreload, this needs some refactoring with the broad template paths and testing before it can work.

To do this, edit the `docker/docker-compose.yml` file and uncomment the lines below `# uncomment for development`.

After this run the following command to mount the volumes:

	make docker-compose-up

Then after a Python file change just restart the relevant service, ie:

	make docker-compose-restart services=app

**notice**: on macOS, depending on the Docker runtime it might take some seconds for file changes to sync from the host OS to the Docker VM. And might result in changes not seeming to come through when restart a service to quickly.

## Debugging/introspection

### Enter container

To enter a container to inspect the filesystem of processes run the following command:

    make docker-compose-exec service=app

This will default to running Bash shell inside the service's container. You can also provide a different command like so:

    make docker-compose-exec service=app cmd="cat /etc/resolv.conf"

## IPv6 support

IPv6 support in the development environment is limited or must be especially configured depending on your setup. On Linux hosts it will mostly work if you have native IPv6. On Mac even with native IPv6 configuration is harder or not possible due to the way Docker (or alternatives) is implemented.

By default IPv6 is not configured. See below for the options to enable IPv6 for your specific setup/scenario.

### No IPv6

Depending on the change/feature you need to develop IPv6 might not be a requirement. For example if you only work on the frontend. In this case missing IPv6 support can be ignored.

TODO: possibility to disable IPv6 tests???

### IPv6 subnet forwarding (Linux only)

TODO: need verification

It is possible to enable IPv6 support in the development environment if your laptop/desktop has a native IPv6 subnet assigned. You can do this by taking a smaller subnet of the host assigned subnet and assign it to the Docker network. This is similar to how the production deployment is done.
This feature is currently limited to Linux systems only because of the way Docker Desktop for Mac/Windows works.

First determine the IPv6 subnet assigned to your system (Run `ip -6 addr` and use the 'scope global' address on your primary interface). For example: if your interface is assigned `2001:db8:1234:0:abcd:1234:5678/64`, then your subnet is `2001:db8:1234:0::/64`.

From this subnet take a smaller subnet (eg: `/80`) like: `2001:db8:1234:0:1::/80`.

If the development environment is currently up, bring it down and remove all volumes/networks: `make docker-compose-down-remove-volumes`

Now change the following values in the `develop.env` file:

- `IPV6_SUBNET_PUBLIC`: change `fd00:42:1::/48` to the smaller subnet determined above (eg: `2001:db8:1234:0:1::/80`)
- `IPV6_GATEWAY_PUBLIC`: replace `fd00:42:1::` with the subnet prefix (eg: `fd00:42:1::1` to `2001:db8:1234:0:1::1`)
- `IPV6_IP_PUBLIC`: replace `fd00:42:1::` with with the subnet prefix (eg: `fd00:42:1::100` to `2001:db8:1234:0:1::100`)
- `IPV6_UNBOUND_IP_PUBLIC`: replace `fd00:42:1::` with with the subnet prefix (eg: `fd00:42:1::101` to `2001:db8:1234:0:1::101`)

Bring the development environment back up: `make docker-compose-up`

### Integration test environment

The integration test environment contains an isolated internal IPv6 network. If the feature/change can be approached without needing to connect to an outside instance but instead using a simulated test target, this would be the way to go. Please refer to the [Integration tests](documentation/Docker-integration-tests.md) document for more information.

### IPv6 tunnel broker

TODO: test implementation and document

### Remote development / VM

If you have access to a remote Linux machine with native IPv6 or are able to setup a local VM with IPv6 support this can be used for remote development. Please also see the [Deployment](documentation/Docker-deployment.md) document for more information and how to setup DNS for the connection tests.

## FAQ

### Why does the environment take so long to come up?

Initially setting up the environment might take a minute or 3 because RabbitMQ is slow on startup and it is a requirement for most other services. If you do not bring down the Rabbitmq service, subsequent changes (up/restart) to the development should run much quicker.