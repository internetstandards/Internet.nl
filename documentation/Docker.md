# Docker / Docker Compose

This project uses Docker images as release artifacts and Docker Compose to orchestrate the application stack.

## Prerequisites

An OCI compatible container runtime is required to run the project. Docker is adviced but any compatible runtime should do like Podman or Colima.

## Building/Running

First build the Docker images for the application using the following command:

    make docker-build

After which the application is accesible on the adres: http://localhost:8080

To run the application stack use the following command:

    make docker-compose-up

The command will wait for the stack to come up completely and be in a healthy state. After which the application is accesible on the address: http://localhost:8080. Logs can be streamed using:

    make docker-compose-logs

Please be aware some features don't work out of the box due to limitations of the environment. IPv6 connectivity is likely to not be working. RPKI tests rely on Routinator syncing up from external databases and will take a while (`docker logs internetnl-routinator-1 -f`). Connection test will not work because it requires external connectivity and DNS records to be setup.

To stop the running stack use:

    make docker-compose-stop

This will keep transient data (databases, etc). The stack can be brought up again with: `make docker-compose-up`.

To completely stop and remove all data from the instance run:

    make compose-down-remove-volumes