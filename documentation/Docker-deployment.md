# Deployment

This document describes how to deploy and configure the Internet.nl application to run on a Linux server. This installation includes all 3 tests and IPv6 but not Batch mode. If this is not applicable to your situation please refer to other deployment documents.

Instructions are limited to setting up the server for the functionality of the application. Security, maintenance and management (eg: firewall, updates, SSH) aspects are out of scope.

## Requirements

- Server running Ubuntu 22.04 LTS
- Public IPv4 address
- Public IPv6 subnet
- Public domain name

The server can be hardware or VM. Minimum is at least 2 cores, 2GB memory and 50GB storage. Recommended 4 cores, 4GB memory 100GB storage. Recommended OS is Ubuntu 22.04 LTS, but any recent Debian/Ubuntu should suffice. Other OS's may be supported but not tested or documented. You should have `root` access to the server.

A fixed public IPv4 address is required. The address may be assigned to the server network primary interface. For example: `192.0.2.1`.

A fixed public IPv6 subnet is required. The subnet should be of size `/80` or bigger. For example if the server has IPv6 address `2001:db8:abcd:1234::1/64` and subnet `2001:db8:abcd:1234::/64` assigned to its primary interface a smaller subnet like `2001:db8:abcd:1234:1::/80` can be used for the container network.

IPv4 and IPv6 traffic may be firewalled but should always maintain the source address of the connection to the server. If firewalled the following ports should be forwarded:

- 80/tcp
- 443/tcp
- 53/tcp
- 53/udp

A public domain name or subdomain is required. It should be possible to set the `A`, `AAAA` and `NS` records on the (sub)domain.

## Server setup

After installation and basic configuration of the OS switch to `root` user.

Run the following command to install required dependencies:

    apt update
    apt install -yqq make git ca-certificates curl gnupg

Setup Docker Apt repository:

    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    echo "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
      "$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" > /etc/apt/sources.list.d/docker.list
    apt update

Install Docker:

    apt install -yqq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

## Application setup

Clone source:

    cd /opt/
    git clone --branch docker --recursive https://github.com/internetstandards/Internet.nl.git
    cd Internet.nl/

Create a configuration file, the following inputs are required:

- `INTERNETNL_DOMAINNAME`:

  Public domain name of the application (eg: example.com).

  This is used as domain to visit the application and as domain for the connection test subdomains.

- `SECRET_KEY`:

  Key used by Django for cryptographic signing, use unique key per instance, can be generated using:

  `docker run -ti --rm --entrypoint python3 django -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())'`

  Be sure to wrap the resulting key in single quotes because it might contain characters that would be interpreted by the shell.

- `IPV4_IP_PUBLIC`:

  Public IPv4 address (eg: `192.0.2.1`)

  This is the address by which the website is accessible over IPv4 on public internet.

  To determine the current IPv4 address you can use: `ip -4 addr show dev eth0` or `curl -4 ifconfig.io`.

- `IPV6_SUBNET_PUBLIC`:

  Public IPv6 subnet (eg: `2001:db8:abcd:1234:1::/80`).

  This is a smaller subnet of the IPv6 subnet assigned to the server.

  To determine the current IPv6 subnet assigned to the server run: `ip -6 addr show dev eth0` (be sure **not** to use the link-local `fe80` address).

- `IPV6_GATEWAY_PUBLIC`:

  Should be set to the first IP in the `IPV6_SUBNET_PUBLIC`, eg: `2001:db8:abcd:1234:1::1`

- `IPV6_IP_PUBLIC`:

  This is the address by which the website is accessible over IPv6 on public internet. This is not the IPv6 address bound the the primary interface. But an address on the `IPV6_SUBNET_PUBLIC`.

  Can be set to any free IPv6 in the `IPV6_SUBNET_PUBLIC` subnet, higher values (eg: `1000`) are recommended to prevent conflicts with automatic assigned addresses, eg: `2001:db8:abcd:1234:1::1000`.

- `IPV6_UNBOUND_IP_PUBLIC`:

  This is the address by which the unbound resolver is accessible over IPv6 on public internet. This is not the IPv6 address bound the the primary interface. But an address on the `IPV6_SUBNET_PUBLIC`.

  Can be set to any free IPv6 in the `IPV6_SUBNET_PUBLIC` subnet, higher values (eg: `1001`) are recommended to prevent conflicts with automatic assigned addresses, eg: `2001:db8:abcd:1234:1::1001`

Use the values determined above to fill in the variables below and run the following command (protip: use ctrl-x ctrl-e in Bash to open a text editor to easily paste and edit the command):

    INTERNETNL_DOMAINNAME=example.com \
    SECRET_KEY='this-is-not-a-secret' \
    IPV4_IP_PUBLIC=192.0.2.1 \
    IPV6_SUBNET_PUBLIC=2001:db8:1::/80 \
    IPV6_GATEWAY_PUBLIC=2001:db8:1::1 \
    IPV6_IP_PUBLIC=2001:db8:1::1000 \
    IPV6_UNBOUND_IP_PUBLIC=2001:db8:1::1001 \
    envsubst < production-dist.env > production.env

Build container images:

    make docker-compose-build environment=production

Spin up instance:

    make docker-compose-up environment=production

This command should complete without an error, indicating the application stack is up and running healthy.

## DNS setup

For accessing the application and connection tests the following DNS records should be configured:

- `A` and `AAAA` records for the website, eg: `example.com` which point to the `IPV4_IP_PUBLIC` and `IPV6_IP_PUBLIC` respectively.
- `A` and `AAAA` records or `CNAME` for connection test, eg: `conn.example.com` which point to the `IPV4_IP_PUBLIC` and `IPV6_IP_PUBLIC` for `A` and `AAAA` or the website domain (`example.com`) for `CNAME`.
- `A` and `AAAA` records for the connection test nameserver, eg: `ns.test-ns-signed.example.com` and `ns.test-ns6-signed.example.com` which point to the `IPV4_IP_PUBLIC` and `IPV6_UNBOUND_IP_PUBLIC` respectively.
- `NS` records for connection tests, eg: `test-ns-signed.example.com` and `test-ns6-signed.example.com` which point to respective `A` and `AAAA` nameserver records.

## Testing

After deployment and DNS setup you can visit the website on eg: `http://example.com` and perform tests manually. Or use the Live test suite to perform automated tests. For this run:

    APP_URLS=http://example.com make live-tests

The Live test suite can be executed from the server or by cloning the repository on your desktop/laptop and executing from there. For more information see: [documentation/Docker-live-tests.md](documentation/Docker-live-tests.md)

## Updating

To update the application stack first update the Git repository with the latest changes:

    cd /opt/Internet.nl/
    git remote update

**notice**: the following command will undo any changes in the repository except for the `production.env` file

    git reset --hard origin/docker
    git submodule update --init --recursive

Then rebuild the application images:

    make docker-compose-build environment=production

Then update the application components:

    make docker-compose-up environment=production
