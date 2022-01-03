## tl;dr

> **Note: "host networking" support required (see issue [#435](https://github.com/internetstandards/Internet.nl/issues/435)).**
>
> According to [docs.docker.com](https://docs.docker.com/network/host/) _"The host networking driver only works on Linux hosts, and is not supported on Docker Desktop for Mac, Docker Desktop for Windows, or Docker EE for Windows Server"_.

```
$ docker-compose pull
# initialize routinator volume
$ docker run --rm -v ${COMPOSE_PROJECT_NAME:-docker}_routinator-tals:/home/routinator/.rpki-cache/tals \
    nlnetlabs/routinator init -f --accept-arin-rpa
$ docker-compose up
$ xdg-open http://localhost:8080/
```

## With your own Redis, RabbitMQ, Routinator and Postgres servers
If using your own Redis, RabbitMQ, Routinator and Postgres servers you don't need Docker Compose, you can use Docker directly with these parameters:
```
--dns 127.0.0.1 --network host \
    -e RABBITMQ_HOST=<IP address or domain name> \
    -e REDIS_HOST=<IP address or domain name> \
    -e ROUTINATOR_HOST=<IP address or domain name:portnumber> \
    -e POSTGRES_HOST=<IP address or domain name> \
    -e POSTGRES_USER=<username> \
    -e POSTGRES_DB=<db name> \
    -e POSTGRES_PASS=<password> \
```

## Tested versions
```
$ lsb_release -d -s
Ubuntu 18.10
$ docker --version
Docker version 18.09.2, build 6247962
$ docker-compose --version
docker-compose version 1.23.2, build 1110ad01
```

## Rebuilding the Docker image
The docker image on Docker Hub is no longer maintained - you will need to use the docker files from this repo.

If you've made changes to the files in your local clone of Internet.nl you can build an image containing those changes by forcing Docker Compose to build the image:
```
$ docker-compose build
```

## Starting a terminal session
If you want to get a terminal session in the running container you can do that like so:
```
$ docker-compose exec app /bin/bash
```

## Backgrounding and cleaning up
To run the containers in the background:
```
$ docker-compose up -d
$ docker-compose down (in another terminal)
```

## Customizing the deployment
There are three ways to customize the deployment:
1. Pass environment variables to docker directly (see the example above).
2. Pass environment variables to Docker Compose by creating a `.env` file containing NAME=VALUE key pairs to override the any of the environment variables that are passed by the `docker-compose.yml` file. See the [Docker Compose documentation](https://docs.docker.com/compose/environment-variables/#pass-environment-variables-to-containers).
3. Create your own Dockerfile using the nlnetlabs/internetnl image as a base, `export DJANGO_SETTINGS_MODULE=/path/to/your/settings.py` and base your `settings.py` file on [`settings.py-dist`](https://github.com/internetstandards/Internet.nl/blob/master/internetnl/settings.py-dist). You can also go even further and override the Docker entrypoint to take complete control.

For further customisation edit `Dockerfile` before running `docker-compose build`.

## Known issues
- Connection testing is not yet possible because it relies upon a specific deployment of Unbound configured as master for subdomains of a test domain that you own.
- Building of Unbound needs to be modified to support the ["Change #defines on top of internetnl/internetnl.c to match test environment"](https://github.com/internetstandards/unbound/blob/internetnl/README.md) build step with user specific domain name details.

## Development
The experimental [squash](https://docs.docker.com/engine/reference/commandline/build/#squash-an-images-layers---squash-experimental) feature is used to reduce the image size from ~2 GiB to ~1.2 GiB. See `--squash` in the [official Docker Build documentation](https://docs.docker.com/engine/reference/commandline/image_build/).

A future improvement could be to use [multi-stage builds](https://docs.docker.com/develop/develop-images/#use-multi-stage-builds) to keep only the final artifacts in the image and to exclude artifacts used only while building dependencies.

## Architecture
The chosen architecture uses four separate containers attached to the host network:
- Main container: Django and Celery.
- Helper containers: Redis, RabbitMQ and PostgreSQL.

A Docker bridge network could in theory be used rather than the host network, but in tests IPv6 outbound connectivity was not working with a bridge network.

The structure could be changed, e.g. to:
- A single Docker image containing all of the helper programs as well and without Docker Compose.
  PRO: Simpler to consume (docker run <imagename> instead of download docker-compose.yml and then docker-compose up).
  CON: Combining lots of services into a single Docker image is [contrary to the Docker way: ["Each container should have only one concern"](https://docs.docker.com/develop/develop-images/#decouple-applications).

- A Hashicorp Terraform definition:
  PRO: Could deploy both with Docker or with a cloud provider.
  PRO: Deployment to a real cloud VM would also possibly enable dynamic creation of necessary DNS zone details to enable connection testing to work.
