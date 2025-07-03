terraform {
  required_providers {
    transip = {
      source = "aequitas/transip"
    }
    hcloud = {
      source = "hetznercloud/hcloud"
    }
    remote = {
      source  = "tenstad/remote"
      version = "0.2.0"
    }
    deepmerge = {
      source  = "isometry/deepmerge"
      version = "1.0.0"
    }
    cloudinit = {
      source  = "hashicorp/cloudinit"
      version = "2.3.7"
    }
  }
}

provider "remote" {
  # Configuration options
}

provider "transip" {
  # API credentials are taken from environment variables TRANSIP_ACCOUNT_NAME and TRANSIP_PRIVATE_KEY
  # which are initialized in the .envrc file using Keyring
}
