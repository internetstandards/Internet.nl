# Automatic deployment using Tofu and Cloudinit

This directory container code which allows Internet.nl instances to be deployed automatically using OpenTofu and Cloudinit. It is currently not an official supported deployment method so there will be no guarantee it will be supported/documented in the future. It is extremely opinionated and only used sometimes for internal development. Consider it an example to develop your own deployment solution.

## Requirements

- Nix & Direnv (dependency management)
- Hetzner (cloud servers)
- Transip (DNS)

## Setup

Setup dependencies and configure credentials

    direnv allow

    echo <<EOF | keyring set transip internetnl
    -----BEGIN PRIVATE KEY-----
    <transip private key>
    -----END PRIVATE KEY-----
    EOF

    keyring set hetzner internetnl
    <hetzner api token>

    tofu init

    cp servers.auto.tfvars.dist servers.auto.tfvars

Now edit `servers.auto.tfvars` to configure which servers and configurations you like and apply to instantiate:

    tofu apply
