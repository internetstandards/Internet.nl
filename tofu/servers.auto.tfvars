servers = {
  # batch6 = {
  #   server_type = "cx22"
  #   version = "latest"
  #   config      = <<-EOT
  #   ENABLE_BATCH=True
  #   CRON_15MIN_RUN_TESTS=True
  #   TEST_DOMAINS_SITE=ijohan.nl,www.ijohan.nl,internet.nl,www.internet.nl,example.nl,www.example.nl
  #   TEST_DOMAINS_MAIL=ijohan.nl,www.ijohan.nl,internet.nl,www.internet.nl,example.nl,www.example.nl
  #   EOT
  # }
  single-1-8-10 = {
    server_type = "cx22"
    version = "1.8.10"
    config      = <<-EOT
    CRON_15MIN_RUN_TESTS=True
    # is hardcoded in tests.py
    # TEST_DOMAINS_SITE=example.nl,example.com
    EOT
  }
  single-1-9-3 = {
    server_type = "cx22"
    version = "1.9.3"
    config      = <<-EOT
    CRON_15MIN_RUN_TESTS=True
    # is hardcoded in tests.py
    # TEST_DOMAINS_SITE=internet.nl,example.nl,example.com,internetsociety.org,ripe.net,surf.nl,ecp.nl,forumstandaardisatie.nl,minez.nl
    EOT
  }
  single-1-10-2 = {
    server_type = "cx22"
    version = "1.10.2"
    config      = <<-EOT
    CRON_15MIN_RUN_TESTS=True
    TEST_DOMAINS_SITE=internet.nl,example.nl,example.com,internetsociety.org,ripe.net,surf.nl,ecp.nl,forumstandaardisatie.nl,minez.nl
    # TEST_DOMAINS_SITE=example.nl,example.com
    # TEST_DOMAINS_SITE=example.nl,example.com,ijohan.nl,www.ijohan.nl,internet.nl,www.internet.nl,www.example.nl
    # TEST_DOMAINS_MAIL=example.nl,example.com
    # TEST_DOMAINS_MAIL=example.nl,example.com,ijohan.nl,www.ijohan.nl,internet.nl,www.internet.nl,www.example.nl
    EOT
  }
  norestart-1-10-2 = {
    server_type = "cx22"
    version = "1.10.2"
    config      = <<-EOT
    CRON_15MIN_RUN_TESTS=True
    CRON_WORKER_RESTART=False
    TEST_DOMAINS_SITE=internet.nl,example.nl,example.com,internetsociety.org,ripe.net,surf.nl,ecp.nl,forumstandaardisatie.nl,minez.nl
    # TEST_DOMAINS_SITE=example.nl,example.com
    # TEST_DOMAINS_SITE=example.nl,example.com,ijohan.nl,www.ijohan.nl,internet.nl,www.internet.nl,www.example.nl
    # TEST_DOMAINS_MAIL=example.nl,example.com
    # TEST_DOMAINS_MAIL=example.nl,example.com,ijohan.nl,www.ijohan.nl,internet.nl,www.internet.nl,www.example.nl
    EOT
  }
}
