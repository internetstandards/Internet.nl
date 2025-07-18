servers = {
  single-1-8-10 = {
    server_type = "cx22"
    version = "1.8.11.dev1-gf647649"
    config      = <<-EOT
    CRON_15MIN_RUN_TESTS=True
    # implicit because this version does not restart workers yet
    # CRON_WORKER_RESTART=False
    TEST_DOMAINS_SITE=ijohan.nl,example.nl,internet.nl
    EOT
  }
  single-1-9-3 = {
    server_type = "cx22"
    version = "1.9.3"
    config      = <<-EOT
    CRON_15MIN_RUN_TESTS=True
    CRON_WORKER_RESTART=True
    TEST_DOMAINS_SITE=ijohan.nl,example.nl,internet.nl
    TEST_DOMAINS_MAIL=
    EOT
  }
  single-1-10-2 = {
    server_type = "cx22"
    version = "1.10.2"
    config      = <<-EOT
    CRON_15MIN_RUN_TESTS=True
    CRON_WORKER_RESTART=True
    TEST_DOMAINS_SITE=ijohan.nl,example.nl,internet.nl
    TEST_DOMAINS_MAIL=
    EOT
  }
  norestart-1-10-2 = {
    server_type = "cx22"
    version = "1.10.2"
    config      = <<-EOT
    CRON_15MIN_RUN_TESTS=True
    CRON_WORKER_RESTART=False
    TEST_DOMAINS_SITE=ijohan.nl,example.nl,internet.nl
    TEST_DOMAINS_MAIL=
    EOT
  }
}


# "1.11.0.dev4-g5fd02a2" 1.10 stop workers 5 minutes before every 15 minutes and start them every 15 minutes
# "1.11.0.dev3-g579901c" 1.10 restart workers sequentially by sending SIGTERM to celery process in container
# "1.10.0.dev5-g3338c47" 1.9  restart workers sequentially by sending SIGTERM to celery process in container
# "1.11.0.dev5-geaf7acf" 1.10 log related exceptions to sentry
