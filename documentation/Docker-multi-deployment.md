# Deploying multiple instances on the same server

*notice*: this is an specialized configuration, intended for development and acceptance testing environments. It is not recommended for normal or production deployments. Copy-paste commands from CI and commands/examples from other documentation do not work directly for multi deployed instances.

It is possible to run multiple instances of the Internet.nl application stack on the same server. This can be useful for development and acceptance testing environments where different branches need to be tested side by side without having to run multiple servers.

However this requires some additional configuration for the additional instances as the public IP addresses and the Docker network subnets used need to be different for each instance.

To keep the configuration files for each instance separate, it is recommended to create a new directory for each instance. Each instance will also have its own Compose project name.

To save on resources the routinator service can be shared between the instances. This requires the routinator service to be running on only the first instance and the other instances to configure the `ROUTINATOR_URL` variable to point to the routinator service on the first instance.

## Requirements

- Additional public IPv4 and IPv6 address pairs bound to the server, one pair for each extra instance
- Unique public (sub)domain names for each IP pair
- Additional server resources (CPU, Memory (~1GB), disk space) depending on the number of instances
- Existing deployment of the Internet.nl application stack (see: [Application setup](Docker-deployment.md#application-setup))

## Renaming initial instance

Bring down the initial instance and rename it to `dev1`, renaming all existing volumes:

    /opt/Internet.nl/docker/compose.sh down
    mv /opt/Internet.nl /opt/Internet.nl-dev1
    cd /var/lib/docker/volumes
    rename 's/prod/dev1/' internetnl-prod_*
    cd /opt/Internet.nl-dev1
    echo INTERNETNL_INSTALL_BASE=/opt/Internet.nl-dev1 >> docker/host.env
    sed -i 's/dev-docker/dev1/' docker/host.env
    sed -i 's/internetnl-prod/internetnl-dev1/' docker/host.env
    /opt/Internet.nl-dev1/docker/compose.sh up --remove-orphans --wait --no-build

Add the following lines to `docker/host.env` and change the IP's to the public IP's for the dev1 instances:

    WEBSERVER_PORT=192.0.2.2:80:80
    WEBSERVER_PORT_TLS=192.0.2.2:443:443
    WEBSERVER_PORT_IPV6=[2001:db8:1::2]:80:80/tcp
    WEBSERVER_PORT_IPV6_TLS=[2001:db8:1::2]:443:443/tcp
    SMTPSERVER_PORT=192.0.2.2:25:25
    SMTPSERVER_PORT_IPV6=[2001:db8:1::2]:25:25

## Adding a new instance

To add a new instance copy the configuration directory from the existing instance to a new path, eg:

    cp -r /opt/Internet.nl-dev1 /opt/Internet.nl-dev2
    cd /opt/Internet.nl-dev2

Modify the `docker/host.env` file with the following steps:

- Change `COMPOSE_PROJECT_NAME` to a unique name, eg: `internetnl-dev2`
- Change `INTERNETNL_DOMAINNAME`, `CONN_TEST_DOMAIN`, `SMTP_EHLO_DOMAIN` and optionally `SENTRY_SERVER_NAME` to the new domain name (eg: `dev2.example.com`)
- Update `ALLOWED_HOSTS` and `CSP_DEFAULT_SRC` values to the new domain name (eg: `dev2.example.com`)
- Change `IPV4_IP_PUBLIC`, `IPV6_IP_PUBLIC`, `IPV6_TEST_ADDR` to the public IPv4/IPv6 addresses specific for this instance
- Update `UNBOUND_PORT_TCP`, `UNBOUND_PORT_UDP`, `UNBOUND_PORT_IPV6_TCP` and `UNBOUND_PORT_IPV6_UDP` to the public IPv4/IPv6 addresses for this instance
- Add `WEBSERVER_PORT`, `WEBSERVER_PORT_TLS`, `WEBSERVER_PORT_IPV6`, `WEBSERVER_PORT_IPV6_TLS`, `SMTPSERVER_PORT`, `SMTPSERVER_PORT_IPV6` with the public IPv4/IPv6 addresses for this instance and the respective ports
- Add `IPV4_SUBNET_PUBLIC`, `IPV4_SUBNET_INTERNAL`, `IPV6_SUBNET_PUBLIC` and `IPV6_GATEWAY_PUBLIC` with unique subnet/address from private address space, this should not conflict with the existing instances. Suggested is to iterate over subnets for the existing instance (`172.16.42.0/24`, `192.168.42.0/24`, `fd00:42:1::/48`, `fd00:42:1::1`) so the first ones would become: `172.16.43.0/24`, `192.168.43.0/24`, `fd00:43:1::/48` and `fd00:43:1::1`.
- Add a `ROUTINATOR_URL` with a URL to the first instance routinator proxy endpoint, so the extra instances don't have to run a resource heavy extra routinator, eg: `https://example.com/routinator/api/v1/validity`. This also requires removing the `routinator` entry from `COMPOSE_PROFILES` on the extra instance.
- Add `INTERNETNL_INSTALL_BASE` with the path to the new instance directory, eg: `/opt/Internet.nl-dev2`

For convenience you can use the following command to create a new `docker/host.env` file:

    INTERNETNL_DOMAINNAME=dev2.example.com \
    COMPOSE_PROJECT_NAME=internetnl-dev2 \
    INTERNETNL_INSTALL_BASE=/opt/Internet.nl-dev2 \
    IPV4_IP_PUBLIC=192.0.2.2 \
    IPV6_IP_PUBLIC=2001:db8:1::2 \
    IPV4_SUBNET_PUBLIC=172.16.43.0/24 \
    IPV4_SUBNET_INTERNAL=192.168.43.0/24 \
    IPV6_SUBNET_PUBLIC=fd00:43:1::/48 \
    IPV6_GATEWAY_PUBLIC=fd00:43:1::1 \
    SENTRY_SERVER_NAME=dev2.example.com \
    ROUTINATOR_URL=https://dev1.internet.nl/routinator/api/v1/validity \
    envsubst < docker/host-multi-dist.env > docker/host.env

Don't forget to remove the `routinator` entry from the `COMPOSE_PROFILES` variable in the `docker/local.env` file:

    sed -i '/,routinator/d' /opt/Internet.nl-dev2/docker/local.env

Please be aware of values from the existing instance's `docker/host.env` file that you might want to bring over, eg: `SENTRY_DSN`.

    grep -E 'SENTRY_(DSN|ENVIRONMENT)' /opt/Internet.nl-dev1/docker/host.env >> /opt/Internet.nl-dev2/docker/host.env

After the `docker/host.env` file has been modified or recreated, run the following command to bring the new instance up:

    docker run -ti --rm --pull=always \
      --volume /var/run/docker.sock:/var/run/docker.sock \
      --volume $HOME/.docker:/root/.docker \
      --volume /opt/Internet.nl-dev2:/opt/Internet.nl \
      --network none \
      --env DOCKER_REGISTRY=ghcr.io/internetstandards \
      ghcr.io/internetstandards/util:latest \
      /deploy.sh

*notice*: please note the `/opt/Internet.nl-dev2` path for the `--volume` argument which makes sure this configuration directory is used instead of the normal `/opt/Internet.nl` path. This should also be applied when running update commands from CI.

If you have manually defined user/password added using the `docker/user_manage.sh` script use the following command to copy them over (~note~: this can be done at any time in the future when users are added to the first instance and doesn't require a restart).

    cp /var/lib/docker/volumes/internetnl-dev1_htpasswd-files/_data/users.htpasswd /var/lib/docker/volumes/internetnl-dev2_htpasswd-files/_data/users.htpasswd

## Useful commands

Getting DS records for all instances:

    for i in {1..5}; do /opt/Internet.nl-dev$i/docker/compose.sh restart unbound;  /opt/Internet.nl-dev$i/docker/compose.sh logs unbound | grep -A2 "Please add the following DS records for domain";done | grep "IN	DS"

Copy password file from `dev1` to all other instances

    for i in {2..4}; do cp /var/lib/docker/volumes/internetnl-dev1_htpasswd-files/_data/users.htpasswd /var/lib/docker/volumes/internetnl-dev${i}_htpasswd-files/_data/users.htpasswd; done
