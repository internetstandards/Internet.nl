# Docker Development Environment

## Development cycle

    make docker-compose-build
    make docker-compose-up

## IPv6 support

TODO: need verification

It is possible to enable IPv6 support in the development environment if your laptop/desktop has a native IPv6 subnet assigned. This feature is currently limited to Linux systems only because of the way Docker Desktop for Mac/Windows works.

First determine the IPv6 subnet assigned to your system (Run `ip -6 addr` and use the 'scope global' address on your primary interface). For example: if your interface is assigned `2001:db8:1234:0:abcd:1234:5678/64`, then your subnet is `2001:db8:1234:0::/64`.

From this subnet take a smaller subnet (eg: `/80`) like: `2001:db8:1234:0:1::/80`.

If the development environment is currently up, bring it down and remove all volumes/networks: `make docker-compose-down-remove-volumes`

Now change the following values in the `develop.env` file:

- `IPV6_SUBNET_PUBLIC`: change `fd00:42:1::/48` to the smaller subnet determined above (eg: `2001:db8:1234:0:1::/80`)
- `IPV6_GATEWAY_PUBLIC`: replace `fd00:42:1::` with the subnet prefix (eg: `fd00:42:1::1` to `2001:db8:1234:0:1::1`)
- `IPV6_IP_PUBLIC`: replace `fd00:42:1::` with with the subnet prefix (eg: `fd00:42:1::100` to `2001:db8:1234:0:1::100`)
- `IPV6_UNBOUND_IP_PUBLIC`: replace `fd00:42:1::` with with the subnet prefix (eg: `fd00:42:1::101` to `2001:db8:1234:0:1::101`)

Bring the development environment back up: `make docker-compose-up`
