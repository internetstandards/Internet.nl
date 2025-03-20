# Deployment

This document describes how to deploy and configure the Internet.nl application to run on a Linux server. This installation includes all 3 tests (Wesite, Email, Connection) and IPv6 but not Batch mode. If this is not applicable to your situation please refer to other deployment documents ([Deployment Batch](Docker-deployment-batch.md)).

Instructions are limited to setting up the server for the functionality of the application. Security, OS maintenance and management (eg: firewall, updates, SSH) aspects are out of scope.

## Overview

The Internet.nl application stack consist of various components like: Python applications, webserver, database, queue and routinator. These components each run in their own container using Docker Compose as orchestration/deployment method. A minimal amount of changes is required on the host OS system to install and run the application.

Below is an overview of the components involved and their connections:

![production container overview](images/production.png)

## Requirements

- Server running Linux (eg: Ubuntu 22.04 LTS)
- Public IPv4 address
- Public IPv6 address
- Public domain name

The server can be hardware or VM. Minimum is at least 2 cores, 4GB memory and 50GB storage. Recommended 4 cores, 8GB memory 100GB storage. Recommended OS is Ubuntu 22.04 LTS, but any recent Debian/Ubuntu should suffice. Other OS's may be supported but not tested or documented. You should have `root` access to the server.

A fixed public IPv4 and IPv6 address are required. These addresses should be bound to the server's network interface. For example: `192.0.2.1` and `2001:db8:1::1`.

IPv4 and IPv6 traffic may be firewalled but should always maintain the source address of the connection to the server. Outgoing traffic should not be filtered. For incoming traffic related packets and the following ports should be accepted on both IPv4 and IPv6:

- 80/tcp
- 443/tcp
- 53/tcp
- 53/udp

Host based firewalling can be setup. But keep in mind that Docker manages port forwarding in the `nat` table, effectively 'bypassing' a firewall in the `filter` table. This is only a concern if you want to restrict access to the ports that the application exposes (`80`, `443`, `53`). For other ports (eg: `22`) you can apply firewall rules as usual, with eg: UFW.

A public domain name or subdomain is required. It should be possible to set the `A`, `AAAA`, `CNAME`, `NS` and `DS` records on the (sub)domain.

## Server setup

After installation and basic configuration of the OS switch to `root` user.

Currently some Docker and Compose versions cause issues during setup (see: `documentation/Docker-getting-started.md#Prerequisites`). The following command will install a file that will prevent installing unsupported versions:

    cat > /etc/apt/preferences.d/internetnl-docker-supported-versions <<EOF
    # prevent installation of unsupported versions of Docker/Compose
    # https://github.com/internetstandards/Internet.nl/pull/1419
    Package: docker-ce
    Pin: version 5:25.*
    Pin-priority: -1

    Package: docker-ce
    Pin: version 5:26.0.*
    Pin-priority: -1

    Package: docker-ce
    Pin: version 5:26.1.0-*
    Pin-priority: -1

    Package: docker-ce
    Pin: version 5:26.1.1-*
    Pin-priority: -1

    Package: docker-ce
    Pin: version 5:26.1.2-*
    Pin-priority: -1

    Package: docker-compose-plugin
    Pin: version 2.24.*
    Pin-priority: -1

    Package: docker-compose-plugin
    Pin: version 2.25.*
    Pin-priority: -1

    Package: docker-compose-plugin
    Pin: version 2.26.*
    Pin-priority: -1

    Package: docker-compose-plugin
    Pin: version 2.27.1-*
    Pin-priority: -1
    EOF

Run the following command to install required dependencies, setup Docker Apt repository, and install Docker:


    apt update && \
    apt install -yqq ca-certificates curl jq gnupg && \
    install -m 0755 -d /etc/apt/keyrings && \
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg && \
    chmod a+r /etc/apt/keyrings/docker.gpg && \
    echo -e "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] \
    https://download.docker.com/linux/"$(. /etc/os-release && echo "$ID $VERSION_CODENAME")" stable\n \
    deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] \
    https://download.docker.com/linux/"$(. /etc/os-release && echo "$ID $VERSION_CODENAME")" test" \
    > /etc/apt/sources.list.d/docker.list && apt update && \
    apt install -yqq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

Configure Docker for IPv6 and Live restore:

    echo '{"experimental": true, "ip6tables": true, "live-restore": true}' > /etc/docker/daemon.json && \
    systemctl stop docker && \
    systemctl start docker

## Application setup

The application deployment configuration consists of a Docker Compose file (`compose.yaml`) and layered environment files (`docker/defaults.env`, `docker/host.env` and `docker/local.env`).

Run the following commands to install the files in the expected location:

    mkdir -p /opt/Internet.nl/docker && \
    cd /opt/Internet.nl/ && \
    docker run --volume /opt/Internet.nl:/opt/Internet.nl ghcr.io/internetstandards/util:latest cp /dist/docker/host-dist.env /opt/Internet.nl/docker/host-dist.env && \
    touch docker/local.env

To create the `docker/host.env` configuration file, the following inputs are required:

- `INTERNETNL_DOMAINNAME`:

  Public domain name of the application (eg: `example.com`).

  This is used as domain to visit the application and as domain for the connection test subdomains.

- `IPV4_IP_PUBLIC`:

  Public IPv4 address (eg: `192.0.2.1`)

  This is the address by which the website and Unbound DNS is accessible over IPv4 on public internet.

  To determine the current IPv4 address you can use: `ip -4 addr show dev eth0` or `curl -4 ifconfig.io`.

- `IPV6_IP_PUBLIC`:

  Public IPv4 address (eg: `2001:db8:1::1`)

  This is the address by which the website and Unbound DNS is accessible over IPv6 on public internet.

  To determine the current IPv4 address you can use: `ip -6 addr show dev eth0` or `curl -6 ifconfig.io`.

All IPv6 addresses must be in condensed form, i.e. `2001:db8:1::1` and not `2001:db8:0000:0000:0000:0000:0000:1`.

Use the values determined above to fill in the variables below and run the following command (protip: use ctrl-x ctrl-e in Bash to open a text editor to easily paste and edit the command):

    INTERNETNL_DOMAINNAME=example.com \
    IPV4_IP_PUBLIC=192.0.2.1 \
    IPV6_IP_PUBLIC=2001:db8:1::1 \
    SENTRY_SERVER_NAME=$(hostname) \
    envsubst < docker/host-dist.env > docker/host.env

After this a `docker/host.env` file is created. This file is host specific and should not be modified unless something changes in the domainname or IP settings. Note that this sets the sentry hostname for convenience, but to completely configure sentry you also need SENTRY_DSN.

For instance specific configuration use the `docker/local.env` file. Please refer to the `docker/defaults.env` file which contains all configurable settings. Please **do not** modify the `docker/defaults.env` file itself as it will be overwritten in updates.

Spin up instance:

    docker run -ti --rm --pull=always \
      --volume /var/run/docker.sock:/var/run/docker.sock \
      --volume $HOME/.docker:/root/.docker \
      --volume /opt/Internet.nl:/opt/Internet.nl \
      --network none \
      --env DOCKER_REGISTRY=ghcr.io/internetstandards \
      ghcr.io/internetstandards/util:latest \
      /deploy.sh

This command will take a long time (up to 30 minutes) due to RPKI data that needs to be synced initially. After that it should complete without an error, indicating the application stack is up and running healthy. You can already prepare continue with the DNS setup below in the meantime.

## DNS setup

See the [Docker DNS setup](Docker-DNS.md).

## Testing your installation

After deployment is complete, all services are healthy and DNS is setup you can visit the website on eg: `https://example.com` and perform tests manually. Or use the Live test suite to perform automated tests. For this run the following command from the deployed machine or anywhere else with Docker:

    APP_URL=https://example.com
    docker pull ghcr.io/internetstandards/test-runner && \
    docker run -ti --rm --env=APP_URLS=$APP_URL ghcr.io/internetstandards/test-runner

For more information see: [documentation/Docker-live-tests.md](Docker-live-tests.md)

## Logging

Log output from containers/services can be obtained using the following command:

    docker compose --project-name=internetnl-prod logs -f

Or only for specific services:

    docker compose --project-name=internetnl-prod logs -f app

These same logs are also sent to the `journald` daemon to be logged by the OS. This can then be used to forward to remote logging, etc.

To view the logs for a specific app through `journald`, eg. for the `app` service, run:

	journalctl CONTAINER_NAME=internetnl-prod-app-1 --follow

Or to view all logs related to the project use:

	journalctl --follow | grep internetnl-prod-

### Task logging

By default task start and completion is not logged. To enable this set the `CELERY_LOG_LEVEL` value to `INFO` in the `docker/local.env` file and apply the change by running the update commands. Worker containers should now log which tasks are started `Task <task name> received` and succeeded `Task <task name and id> succeeded in <time>s:`.

## Troubleshooting/mitigation

When things don't seem to be working as expected and the logs don't give clear indications of the cause the first thing to do is check the status of the running containers/services:

    docker compose --project-name=internetnl-prod  ps -a

Or use this command to omit the `COMMAND` and `PORTS` columns for a more compact view with only relevant information:

    docker compose --project-name=internetnl-prod  ps -a --format "table {{.Name}}\t{{.Image}}\t{{.Service}}\t{{.RunningFor}}\t{{.Status}}"

Containers/services should have a `STATUS` of `Up` and there should be no containers/services with `unhealthy`. The `db-migrate` having status `Exited (0)` is expected. Containers/services with a short uptime (seconds/minutes) might indicate it restarted recently due to an error.

If a container/service is not up and healthy the cause might be deduced by inspecting the container/service state, eg for the app container/service:

    docker inspect internetnl-prod-app-1 --format "{{json .State}}" | jq

It might be possible not all containers that should be running are running. To have Docker Compose check the running instance and bring up any missing components run:

    env -i docker compose --env-file=docker/defaults.env --env-file=docker/host.env --env-file=docker/local.env up --wait --no-build

If this does not solve the issue you might want to reset the instance by bringing everything down and up again:

    docker compose --project-name=internetnl-prod down
    env -i docker compose --env-file=docker/defaults.env --env-file=docker/host.env --env-file=docker/local.env up --wait --no-build

If this does not work problems might lay deeper and OS level troubleshooting might be required.

## Autohealing

Critial containers/services have Docker healthchecks configured. These run at a configured interval to verify the correct functioning of the services. If a service is unhealthy for too long the Docker daemon will restart the service.

### Known issues

#### Internal Docker DNS not working

Docker Compose relies on an internal DNS resolver to resolve container/services names so the services can communicate via those names (eg: webserver to app, app to PostgreSQL). The internal DNS resolver might become unavailable. This might happen if the system is resource constrained (eg: low memory) and the resolver is OOM killed. This manifests in the application/monitoring becoming unavailable (`502` errors) and logs lines like:

    2023/07/24 07:39:18 [error] 53#53: recv() failed (111: Connection refused) while resolving, resolver: 127.0.0.11:53

The issue can be resolved by restarting the application:

    docker compose --project-name=internetnl-prod restart

## Updating

To update the application stack to the latest release run the following command, which will first update the `docker/defaults.env` and `docker/compose.yaml` files, then pull the latest versions of the prebuild images and update the application components:

    docker run -ti --rm --pull=always --network none \
      --volume /var/run/docker.sock:/var/run/docker.sock \
      --volume $HOME/.docker:/root/.docker \
      --volume /opt/Internet.nl:/opt/Internet.nl \
      --env DOCKER_REGISTRY=ghcr.io/internetstandards \
      ghcr.io/internetstandards/util:latest \
      /deploy.sh

This will update the deployment with the latest release: https://github.com/internetstandards/Internet.nl/releases

If you want to update to a specific tagged version release, e.g. `1.8.8`, use the same update command but replace latest with the version number:

    docker run -ti --rm --pull=always --network none \
      --volume /var/run/docker.sock:/var/run/docker.sock \
      --volume $HOME/.docker:/root/.docker \
      --volume /opt/Internet.nl:/opt/Internet.nl \
      --env DOCKER_REGISTRY=ghcr.io/internetstandards \
      ghcr.io/internetstandards/util:1.8.8 \
      /deploy.sh

### Auto update

By setting the variable `AUTO_UPDATE_TO` in the `/opt/Internet.nl/docker/local.env` auto updating will be enabled. The application will check every 15 minutes if there is a update available and deploy it automatically. This is useful for development/acceptance environments that want to stay up to date with a feature or the `main` branch. It is not recommended for production environments!

This variable can be set to either of these values:

- `latest`: update to latest stable release: https://github.com/internetstandards/Internet.nl/releases
- `main`: update to latest release on the `main` branch
- `<NUMBER>-merge`: update to the latest build of that Pull Request number

Auto upgrades are performed by the `cron-docker` container/service. Progress/errors can be viewed by inspecting the container's logs:

    docker compose --project-name=internetnl-prod logs --follow cron-docker

To manually kick off the update process use the following command:

    docker compose --project-name=internetnl-prod exec cron-docker /etc/periodic-docker/15min/auto_update

**notice**: the update logging might be cut-off at the end because the `cron-docker` container/service will be restarted in the process.

Every time a deploy is performed a entry is added at the bottom of the `docker/local.env` file which indicated the latest release. For example:

    RELEASE='1.9.0.dev142-g118b811-auto_update' # deploy Fri Oct 11 11:42:35 UTC 2024

This variable is used to determine the current version to be deployed or which image version to used when bringing container up. Earlier entries can be safely removed but the last line containing `RELEASE=` must stay in place.

## Downgrading/rollback

In essence downgrading is the same procedure as upgrading. For example, to roll back to version `1.7.0` run:

    docker run -ti --rm --pull=always \
      --volume /var/run/docker.sock:/var/run/docker.sock \
      --volume $HOME/.docker:/root/.docker \
      --volume /opt/Internet.nl:/opt/Internet.nl \
      --network none \
      --env DOCKER_REGISTRY=ghcr.io/internetstandards \
      ghcr.io/internetstandards/util:1.7.0 \
      /deploy.sh

**notice**: depending on the complexity of the previous upgrade a downgrade might involve more steps. This will mostly be the case when database schema's change. In those cases, restoring a backup of the database might be required for a rollback. This will be noted in the release notes if this is the case.

## HTTPS/Letsencrypt

By default the installation will try to request a HTTPS certificate with Letsencrypt for the domain and it's subdomains. If this is not possible it will fall back to a self-signed 'localhost' certificate. If requesting a certificate fails you can debug it by viewing the logs using:

    docker compose --project-name=internetnl-prod logs webserver

and

    docker compose --project-name=internetnl-prod exec webserver cat /var/log/letsencrypt/letsencrypt.log

It may take a few minutes after starting for the Letsencrypt certificates to be registered and loaded.

If the log file cannot be found this mean the Letsencrypt configuration step has not run because there are no new certificates to be configured.

## Batch API

Besides the single scan webpage, the Internet.nl application also contains a Batch API. This is disabled by default on normal installations. Please refer to [Deployment Batch](Docker-deployment-batch.md) for more information.

## Metrics (grafana/prometheus)

The default deployment includes a metrics collection system. It consists of a Prometheus metrics server with various exporters and a Grafana frontend. To view metrics and graphs visit: `https://example.com/grafana/`. Authentication is configured using the `MONITORING_AUTH_RAW` variable.

Also see: [Metrics](Docker-metrics.md)

## Monitoring/alerting

Though the metrics collection system described above can be used for monitoring on the application level it is not suited for alerting or monitoring when the system is under cricital load, due to it running within the same Docker environment.

For the best reliability it is advised to setup monitoring checks external to the server to verify the health of the application components. Because this is very specific to the environment in which the server is running we can only provide generic instructions on what to monitoring.

Basic system checks:

- CPU
- memory/swap
- free disk space on `/var`

All stateful data resides in persistent Docker volumes under `/var/lib/docker/volumes`, a large amount of non-stateful data (ie: images/container volumes) is stored under `/var/lib/docker`.

- Docker daemon status

Because the entire application runs in the Docker container engine it should be monitored for running status. For this check the systemd state of the `docker` unit with for example:

	systemctl is-active docker

This will return a 0 exit code if everything is as expected. Due to Docker being configured with `live-restore`, the daemon itself being down has no direct and immediate impact on the application. But selfhealing behaviour and further interaction with the services will be unavailable.

- Critital application containers/services status

All containers/services critical to the application's primary functionality have a Docker healthcheck configured. This will run at an configured interval to verify the proper operation of the service.

To verify the health status of the critial services use these commands:

	docker inspect --format='{{.State.Health.Status}}' internetnl-prod-webserver-1|grep -qw healthy
	docker inspect --format='{{.State.Health.Status}}' internetnl-prod-app-1|grep -qw healthy
	docker inspect --format='{{.State.Health.Status}}' internetnl-prod-worker-1|grep -qw healthy
	docker inspect --format='{{.State.Health.Status}}' internetnl-prod-beat-1|grep -qw healthy
	docker inspect --format='{{.State.Health.Status}}' internetnl-prod-postgres-1|grep -qw healthy
	docker inspect --format='{{.State.Health.Status}}' internetnl-prod-redis-1|grep -qw healthy
	docker inspect --format='{{.State.Health.Status}}' internetnl-prod-rabbitmq-1|grep -qw healthy
	docker inspect --format='{{.State.Health.Status}}' internetnl-prod-unbound-1|grep -qw healthy
	docker inspect --format='{{.State.Health.Status}}' internetnl-prod-routinator-1|grep -qw healthy
	docker inspect --format='{{.State.Health.Status}}' internetnl-prod-resolver-validating-1|grep -qw healthy

The services `webserver`, `app`, `postgres` and `redis` are critical for the user facing HTTP frontend, no page will show if these are not running. The services `worker`, `rabbitmq`, `routinator`, `unbound` and `resolver-validating` are additionally required for new tests to be performed. The `beat` service is required for updating hall-of-fame. For Batch Deployment this is however a critical service to schedule batch tests submitted via the API.

### Periodic tests

There is a cron available which, when enabled, will test a set of configured domains and output metrics about this (elapsed time, scores, etc). This is usefull for monitoring the overall state of the application stack. To enable and configure it for testing against for example the `example.com` domain, add the following variables to `docker/local.env`:

    CRON_15MIN_RUN_TESTS=True
    TEST_DOMAINS_SITE=example.com
    TEST_DOMAINS_MAIL=example.com

You can specify multiple domains as a comma separated list, eg: `TEST_DOMAINS_SITE=example.com,example.nl`.

### Alerting emails/alertmanager

A Prometheus Alertmanager service is available but disabled by default. Enabling this will allow you to configure alert emails to be sent whenever the periodic tests fail to complete in a reasonable time, indicating an issue with the application.

To enable and configure the Alertmanager add the following lines to `docker/local.env` and adjust the values to be applicable for your environment:

    COMPOSE_PROFILES=alertmanager,monitoring,routinator
    ALERTMANAGER_MAIL_TO=rcpt1@example.com,rcpt2@example.com
    ALERTMANAGER_MAIL_FROM=noreply@example.com
    ALERTMANAGER_SMTP_HOST=smtp.example.com
    ALERTMANAGER_SMTP_USER=example
    ALERTMANAGER_SMTP_PASSWORD=example

The SMTP server is expected to use TLS, there is no way to disable this setting. The port used is `587` and can be customized using the `ALERTMANAGER_SMTP_PORT` variable.

The email subject can be customized using the `ALERTMANAGER_SUBJECT` variable, see `docker/defaults.env` for details.

Current alert status can seen at: https://example.com/prometheus/alerts or https://example.com/alertmanager

If notification emails are not being sent even though alert status shows red see Alertmanager logging for debugging:

    docker compose --project-name=internetnl-prod logs --follow alertmanager

## Restricting access

By default the installation is open to everyone. If you like to restrict access you can do so by either using HTTP Basic Authentication or IP allow/deny lists.

### HTTP Basic Authentication

Site wide HTTP Basic Authentication is enabled with the `AUTH_ALL_URLS` variable.

To manage users, call the `/opt/Internet.nl/docker/user_manage.sh` script. This takes two arguments: an operation
and a username. The operation can be `add_update` to add or update a user's password, `delete` to delete a user,
and `verify` to verify a user's existence and password. Passwords are entered interactively.

If you would like users on the host to manage batch users, set sudo access for this script.

### IP allow/deny lists

Site wide IP(v6) allow lists can be configured by specifying the `ALLOW_LIST` variable. It should contain a comma separated list of IP(v6) addresses or subnets.

For example, to only allow the IP addresses `198.51.100.1` and `2001:db8:2::1` access add the following in the `docker/local.env` file:

    ALLOW_LIST="198.51.100.1,2001:db8:2::1"

### Combining HTTP Basic Authentication and IP allow lists

When adding both users and IPs in `ALLOW_LIST`, users connecting from an IP in the allow list won't be prompted for a password.

## Renewing DNSSEC after IP/hostname change

After changing the IP or hostname in the `docker/host.env` file run:

    env -i docker compose --env-file=docker/defaults.env --env-file=docker/host.env --env-file=docker/local.env up --wait --no-build

to update the DNSSEC accordingly.

When the hostname is changed, update upstream DNSSEC keys with the new values from:

    docker logs internetnl-prod-unbound-1 2>&1 | grep -A2 "Please add the following DS records for domain"

## State/backups/restores/migration

All stateful date for the application stack is stored in Docker Volumes. For backup and DR purposes make sure to include all `/var/lib/docker/volumes/internetnl_*` directories in your snapshot/backup. The directory `internetnl_routinator` can be omited as it contains a cache of externally fetched data.

Daily and weekly database dumps are written to the `/var/lib/docker/volumes/internetnl-prod_postgres-backups/` directory.

When recovering or migrating to a new server first the "Server Setup" should be done then these directories should be restored, after which the "Application Setup" can be done.

## Impact of deployment host/network on test results

The IP and network on which you deploy your instance may have some impact on test results.
Most significantly, this affects test targets hosted in an RPKI invalid prefix. While the RPKI test will always detect
this, if your network or its upstreams do RPKI origin validation, other tests with this target will time out as they
can not reach the target. If there is no (or partial) validation, other tests will report the target as reachable,
even though it may not be for the many networks that now do RPKI origin validation. In either case, the RPKI test will
show the correct result.

If you use an IP address with a poor reputation, or included in block lists, this may cause some tests to show
an unreachable target. This is most likely for email tests, but has been seen for some other tests too.

## Deploying multiple instances on the same server

*notice*: this is an specialized configuration, intended for development and acceptance testing environments. It is not recommended for normal or production deployments.

It is possible to run multiple instances of the Internet.nl application stack on the same server. This can be useful for development and acceptance testing environments where different branches need to be tested side by side without having to run multiple servers.

However this requires some additional configuration for the additional instances as the public IP addresses and the Docker network subnets used need to be different for each instance.

To keep the configuration files for each instance separate, it is recommended to create a new directory for each instance. Each instance will also have its own Compose project name.

To save on resources the routinator service can be shared between the instances. This requires the routinator service to be running on only the first instance and the other instances to configure the `ROUTINATOR_URL` variable to point to the routinator service on the first instance.

### Requirements

- Additional public IPv4 and IPv6 address pairs bound to the server, one pair for each extra instance
- Unique public (sub)domain names for each IP pair
- Additional server resources (CPU, Memory (~1GB), disk space) depending on the number of instances
- Existing deployment of the Internet.nl application stack (see: [Application setup](#application-setup))

### Adding a new instance

To add a new instance copy the configuration directory from the existing instance to a new path, eg:

    cp -r /opt/Internet.nl /opt/Internet.nl-dev1
    cd /opt/Internet.nl-dev1

Modify the `docker/host.env` file with the following steps:

- Change `COMPOSE_PROJECT_NAME` to a unique name, eg: `internetnl-dev1`
- Change `INTERNETNL_DOMAINNAME`, `CONN_TEST_DOMAIN`, `SMTP_EHLO_DOMAIN` and optionally `SENTRY_SERVER_NAME` to the new domain name (eg: `dev1.example.com`)
- Update `ALLOWED_HOSTS` and `CSP_DEFAULT_SRC` values to the new domain name (eg: `dev1.example.com`)
- Change `IPV4_IP_PUBLIC`, `IPV6_IP_PUBLIC`, `IPV6_TEST_ADDR` to the public IPv4/IPv6 addresses specific for this instance
- Update `UNBOUND_PORT_TCP`, `UNBOUND_PORT_UDP`, `UNBOUND_PORT_IPV6_TCP` and `UNBOUND_PORT_IPV6_UDP` to the public IPv4/IPv6 addresses for this instance
- Add `WEBSERVER_PORT`, `WEBSERVER_PORT_TLS`, `WEBSERVER_PORT_IPV6`, `WEBSERVER_PORT_IPV6_TLS` with the public IPv4/IPv6 addresses for this instance and the respective ports
- Add `IPV4_SUBNET_PUBLIC`, `IPV4_SUBNET_INTERNAL`, `IPV6_SUBNET_PUBLIC` and `IPV6_GATEWAY_PUBLIC` with unique subnet/address from private address space, this should not conflict with the existing instances. Suggested is to iterate over subnets for the existing instance (`172.16.42.0/24`, `192.168.42.0/24`, `fd00:42:1::/48`, `fd00:42:1::1`) so the first ones would become: `172.16.43.0/24`, `192.168.43.0/24`, `fd00:43:1::/48` and `fd00:43:1::1`.
- Add a `ROUTINATOR_URL` with a URL to the first instance routinator proxy endpoint, so the extra instances don't have to run a resource heavy extra routinator, eg: `https://example.com/routinator/api/v1/validity`. This also requires removing the `routinator` entry from `COMPOSE_PROFILES` on the extra instance.

For convenience you can use the following command to create a new `docker/host.env` file:

    INTERNETNL_DOMAINNAME=dev1.example.com \
    COMPOSE_PROJECT_NAME=internetnl-dev1 \
    IPV4_IP_PUBLIC=192.0.2.2 \
    IPV6_IP_PUBLIC=2001:db8:1::2 \
    IPV4_SUBNET_PUBLIC=172.16.43.0/24 \
    IPV4_SUBNET_INTERNAL=192.168.43.0/24 \
    IPV6_SUBNET_PUBLIC=fd00:43:1::/48 \
    IPV6_GATEWAY_PUBLIC=fd00:43:1::1 \
    SENTRY_SERVER_NAME=dev1.example.com \
    ROUTINATOR_URL=https://example.com/routinator/api/v1/validity \
    envsubst < docker/host-multi-dist.env > docker/host.env

Don't forget to remove the `routinator` entry from the `COMPOSE_PROFILES` variable in the `docker/local.env` file:

    sed -i '/,routinator/d' /opt/Internet.nl-dev1/docker/local.env

Please be aware of values from the existing instance's `docker/host.env` file that you might want to bring over, eg: `SENTRY_DSN`.

    grep -E 'SENTRY_(DSN|ENVIRONMENT)' /opt/Internet.nl/docker/host.env >> /opt/Internet.nl-dev1/docker/host.env

After the `docker/host.env` file has been modified or recreated, run the following command to bring the new instance up:

    docker run -ti --rm --pull=always \
      --volume /var/run/docker.sock:/var/run/docker.sock \
      --volume $HOME/.docker:/root/.docker \
      --volume /opt/Internet.nl-dev1:/opt/Internet.nl \
      --network none \
      --env DOCKER_REGISTRY=ghcr.io/internetstandards \
      ghcr.io/internetstandards/util:latest \
      /deploy.sh

*notice*: please note the `/opt/Internet.nl-dev1` path for the `--volume` argument which makes sure this configuration directory is used instead of the normal `/opt/Internet.nl` path. This should also be applied when running update commands from CI.
