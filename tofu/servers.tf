locals {
  domain   = "locohost.nl"
  ssh_keys = ["johan@ijohan.nl"]

}

variable "servers" {
  type = map(object({
      server_type = string
      version = string
      config = string
    })
  )
}

variable "credentials" {
  type = object({
    MONITORING_AUTH_RAW= string
    ALLOW_LIST = string
    SENTRY_DSN = string
  })
}

resource "terraform_data" "compose-up" {
  for_each = hcloud_server.internetnl

  triggers_replace = [
    var.servers[each.key],
    var.credentials
  ]

  connection {
    type  = "ssh"
    user  = "root"
    agent = true
    host  = each.value.ipv4_address
  }

  provisioner "file" {
    destination = "/opt/Internet.nl/docker/local.env"
    content     = <<-EOT
    ${var.servers[each.key].config}
    MONITORING_AUTH_RAW='${var.credentials.MONITORING_AUTH_RAW}'
    ALLOW_LIST='${var.credentials.ALLOW_LIST}'
    SENTRY_DSN='${var.credentials.SENTRY_DSN}'
    RELEASE='${var.servers[each.key].version}'
    EOT
  }

  provisioner "remote-exec" {
    inline = [
      "cd /opt/Internet.nl",
      <<-EOT
      %{ if startswith(var.servers[each.key].version, "1.8") }
      curl -sSfO --output-dir docker "https://raw.githubusercontent.com/internetstandards/Internet.nl/v${var.servers[each.key].version}/docker/defaults.env"
      curl -sSfO --output-dir docker "https://raw.githubusercontent.com/internetstandards/Internet.nl/v${var.servers[each.key].version}/docker/host-dist.env"
      curl -sSfO --output-dir docker "https://raw.githubusercontent.com/internetstandards/Internet.nl/v${var.servers[each.key].version}/docker/docker-compose.yml"
      docker compose --env-file=docker/defaults.env --env-file=docker/host.env --env-file=docker/local.env up --wait --no-build
      %{ else }
      docker run --rm --pull=always --volume /var/run/docker.sock:/var/run/docker.sock --volume /opt/Internet.nl:/opt/Internet.nl --network none ghcr.io/internetstandards/util:${var.servers[each.key].version} /deploy.sh
      %{ endif }
      EOT
    ]
  }
}

data "transip_domain" "locohost" {
  name = local.domain
}

data "cloudinit_config" "internetnl" {
  for_each = var.servers

  gzip          = false
  base64_encode = false

  part {
    filename     = "cloud-config.yaml"
    content_type = "text/cloud-config"

    content = yamlencode({
      write_files = [
        {
          path    = "/etc/docker/daemon.json"
          content = "{\"experimental\": true, \"ip6tables\": true, \"live-restore\": true}"
        },
        {
          path    = "/opt/Internet.nl/docker/local.env"
          content = each.value.config
        }
      ]

      runcmd = [
          <<-EOT
          apt update
          apt install -yqq ca-certificates curl jq gnupg
          install -m 0755 -d /etc/apt/keyrings
          curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor > /etc/apt/keyrings/docker.gpg
          chmod a+r /etc/apt/keyrings/docker.gpg
          echo "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/"$(. /etc/os-release && echo "$ID $VERSION_CODENAME")" stable\n deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/"$(. /etc/os-release && echo "$ID $VERSION_CODENAME")" test" > /etc/apt/sources.list.d/docker.list && apt update
          apt install -yqq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
          mkdir -p /opt/Internet.nl/docker
          cd /opt/Internet.nl/
          %{ if startswith(each.value.version, "1.8") }
            curl -sSfO --output-dir docker "https://raw.githubusercontent.com/internetstandards/Internet.nl/v${each.value.version}/docker/defaults.env"
            curl -sSfO --output-dir docker "https://raw.githubusercontent.com/internetstandards/Internet.nl/v${each.value.version}/docker/host-dist.env"
            curl -sSfO --output-dir docker "https://raw.githubusercontent.com/internetstandards/Internet.nl/v${each.value.version}/docker/docker-compose.yml"
            INTERNETNL_DOMAINNAME=$(hostname -f) \
            IPV4_IP_PUBLIC=$(curl -4 ifconfig.io) \
            IPV6_IP_PUBLIC=$(curl -6 ifconfig.io) \
            SENTRY_SERVER_NAME=$(hostname) \
            envsubst < docker/host-dist.env > docker/host.env
            echo "MONITORING_AUTH_RAW='${var.credentials.MONITORING_AUTH_RAW}'" >> docker/local.env
            echo "ALLOW_LIST='${var.credentials.ALLOW_LIST}'" >> docker/local.env
            echo "SENTRY_DSN='${var.credentials.SENTRY_DSN}'" >> docker/local.env
            echo "RELEASE='${each.value.version}'" >> docker/local.env
            docker compose --env-file=docker/defaults.env --env-file=docker/host.env --env-file=docker/local.env up --wait --no-build
          %{ else }
            docker run --volume /opt/Internet.nl:/opt/Internet.nl ghcr.io/internetstandards/util:${each.value.version} cp /dist/docker/host-dist.env /opt/Internet.nl/docker/host-dist.env
            INTERNETNL_DOMAINNAME=$(hostname -f) \
            IPV4_IP_PUBLIC=$(curl -4 ifconfig.io) \
            IPV6_IP_PUBLIC=$(curl -6 ifconfig.io) \
            SENTRY_SERVER_NAME=$(hostname) \
            envsubst < docker/host-dist.env > docker/host.env
            echo "MONITORING_AUTH_RAW='${var.credentials.MONITORING_AUTH_RAW}'" >> docker/local.env
            echo "ALLOW_LIST='${var.credentials.ALLOW_LIST}'" >> docker/local.env
            echo "SENTRY_DSN='${var.credentials.SENTRY_DSN}'" >> docker/local.env
            echo "RELEASE='${each.value.version}'" >> docker/local.env
            docker run --rm --pull=always   --volume /var/run/docker.sock:/var/run/docker.sock   --volume /opt/Internet.nl:/opt/Internet.nl   --network none   ghcr.io/internetstandards/util:${each.value.version}   /deploy.sh
          %{ endif }
          EOT
      ]
    })
  }
}

resource "hcloud_server" "internetnl" {
  for_each = var.servers

  location = "nbg1"

  name        = "${each.key}.${local.domain}"
  server_type = each.value.server_type

  # firewall_ids = [
  #   hcloud_firewall.generic_firewall.id,
  # ]

  image     = "ubuntu-22.04"
  user_data = data.cloudinit_config.internetnl[each.key].rendered

  ssh_keys = local.ssh_keys

  lifecycle {
    # prevent destroying/recreating server when cloudinit or sshkeys change
    ignore_changes = [user_data, ssh_keys]
  }
  # prevent accidental delete via hetzner API
  delete_protection  = false
  rebuild_protection = false

  connection {
    type        = "ssh"
    user        = "root"
    agent = true
    host        = self.ipv4_address
  }

  provisioner "remote-exec" {
    inline = [
      <<-EOT
      if ! cloud-init status --wait; then
        cat /var/log/cloud-init-output.log
        exit 1
      fi
      EOT
    ]
  }

  provisioner "local-exec" {
    command     = "ssh-keyscan -4 -t ed25519 ${self.ipv4_address} | grep -v '#' >> $HOME/.ssh/known_hosts;"
    interpreter = ["/bin/bash", "-c"]
  }
}

resource "hcloud_rdns" "hetzner_server_server_rdns_v4" {
  for_each = hcloud_server.internetnl

  server_id  = each.value.id
  ip_address = each.value.ipv4_address
  dns_ptr    = "${each.key}.${local.domain}"
}

resource "hcloud_rdns" "hetzner_server_server_rdns_v6" {
  for_each = hcloud_server.internetnl

  server_id  = each.value.id
  ip_address = each.value.ipv6_address
  dns_ptr    = "${each.key}.${local.domain}"
}

resource "transip_dns_record" "hetzner_server_a" {
  for_each = hcloud_server.internetnl

  domain  = data.transip_domain.locohost.id
  name    = each.key
  type    = "A"
  expire  = 60 * 5
  content = [each.value.ipv4_address]
}

resource "transip_dns_record" "hetzner_server_aaaa" {
  for_each = hcloud_server.internetnl

  domain  = data.transip_domain.locohost.id
  name    = each.key
  type    = "AAAA"
  expire  = 60 * 5
  content = [each.value.ipv6_address]
}

resource "transip_dns_record" "hetzner_server_a_conn" {
  for_each = hcloud_server.internetnl

  domain  = data.transip_domain.locohost.id
  name    = "conn.${each.key}"
  type    = "A"
  expire  = 60 * 5
  content = [each.value.ipv4_address]
}

resource "transip_dns_record" "hetzner_server_aaaa_conn" {
  for_each = hcloud_server.internetnl

  domain  = data.transip_domain.locohost.id
  name    = "conn.${each.key}"
  type    = "AAAA"
  expire  = 60 * 5
  content = [each.value.ipv6_address]
}

output "urls" {
  value = {
    for k, v in hcloud_server.internetnl : k => "https://${k}.${local.domain}"
  }
}
