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
    version = "1.10.0.dev5-g3338c47"
    config      = <<-EOT
    CRON_15MIN_RUN_TESTS=True
    CRON_WORKER_RESTART=True
    TEST_DOMAINS_SITE=ijohan.nl,example.nl,example.com
    TEST_DOMAINS_MAIL=
    WORKER_REPLICAS=5
    EOT
  }
  single-1-10-2 = {
    server_type = "cx22"
    # says 1.11 but is based on v1.10.2 tag, maybe something to do with the setuptools_scm version tool?
    version = "1.11.0.dev3-g579901c"
    config      = <<-EOT
    CRON_15MIN_RUN_TESTS=True
    CRON_WORKER_RESTART=True
    TEST_DOMAINS_SITE=ijohan.nl,example.nl,example.com
    TEST_DOMAINS_MAIL=
    WORKER_REPLICAS=1
    EOT
  }
  norestart-1-10-2 = {
    server_type = "cx22"
    version = "1.11.0.dev4-g5fd02a2"
    config      = <<-EOT
    CRON_15MIN_RUN_TESTS=True
    CRON_WORKER_RESTART=True
    TEST_DOMAINS_SITE=ijohan.nl,example.nl,example.com
    TEST_DOMAINS_MAIL=
    EOT
  }
}


# "1.11.0.dev4-g5fd02a2" stop workers 5 minutes before every 15 minutes and start them every 15 minutes
# "1.11.0.dev3-g579901c" restart workers sequentially by sending SIGTERM to celery process in container
# "1.10.0.dev5-g3338c47" restart workers sequentially by sending SIGTERM to celery process in container
