servers = {
  single-1-8-10 = {
    server_type = "cx22"
    version = "1.8.11.dev1-gf647649"
    config      = <<-EOT
    CRON_15MIN_RUN_TESTS=True
    # implicit because this version does not restart workers yet
    # CRON_WORKER_RESTART=False
    TEST_DOMAINS_SITE=ijohan.nl,example.nl,example.com
    EOT
  }
  single-1-9-3 = {
    server_type = "cx22"
    # says 1.10 but is based on v1.9.3 tag, maybe something to do with the setuptools_scm version tool?
    version = "1.10.0.dev2-gf422512"
    config      = <<-EOT
    CRON_15MIN_RUN_TESTS=True
    CRON_WORKER_RESTART=True
    TEST_DOMAINS_SITE=ijohan.nl,example.nl,example.com
    TEST_DOMAINS_MAIL=
    EOT
  }
  single-1-10-2 = {
    server_type = "cx22"
    version = "1.10.2"
    config      = <<-EOT
    CRON_15MIN_RUN_TESTS=True
    CRON_WORKER_RESTART=True
    TEST_DOMAINS_SITE=ijohan.nl,example.nl,example.com
    TEST_DOMAINS_MAIL=
    EOT
  }
  norestart-1-10-2 = {
    server_type = "cx22"
    version = "1.10.2"
    config      = <<-EOT
    CRON_15MIN_RUN_TESTS=True
    CRON_WORKER_RESTART=True
    TEST_DOMAINS_SITE=ijohan.nl,example.nl,example.com
    TEST_DOMAINS_MAIL=
    EOT
  }
}
