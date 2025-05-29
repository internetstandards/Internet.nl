# Docker container profiles overview

This overview was last generated at 2025-05-27T12:11:00Z with `make update_container_documentation`.


| container             | profiles     | description                                                                                                                      |
|-----------------------|--------------|----------------------------------------------------------------------------------------------------------------------------------|
| webserver             |              | nginx proxy container, also runs certbot                                                                                         |
| app                   |              | django container                                                                                                                 |
| db-migrate            |              | django DB migrations, runs to completion and exits with 0                                                                        |
| worker                |              |                                                                                                                                  |
| worker-nassl          |              | worker for queue with potential memory leak                                                                                      |
| worker-slow           |              | worker for slow and long running tasks that could require a lot of memory (eg: hof update)                                       |
| beat                  |              | celery task queue                                                                                                                |
| redis                 |              | redis caches state, also used for:<br>- MAC address lookup<br>- Django page cache<br>- client DNS resolver IPs in connectiontest |
| rabbitmq              |              | rabbitmq message-broker                                                                                                          |
| postgres              |              | database                                                                                                                         |
| routinator            | routinator   | for RPKI                                                                                                                         |
| unbound               |              | unbound DNS server used for connection test                                                                                      |
| resolver-validating   |              | unbound resolver used for ldns-dane that require DNSSEC validation                                                               |
| cron                  |              | cron with periodic tasks                                                                                                         |
| cron-docker           |              | cron daemon with access to Docker socket but no networking                                                                       |
| grafana               | monitoring   |                                                                                                                                  |
| prometheus            | monitoring   |                                                                                                                                  |
| alertmanager          | alertmanager | requires monitoring profile                                                                                                      |
| postgresql-exporter   | monitoring   |                                                                                                                                  |
| redis-exporter        | monitoring   |                                                                                                                                  |
| statsd-exporter       | monitoring   |                                                                                                                                  |
| celery-exporter       | monitoring   |                                                                                                                                  |
| node-exporter         | monitoring   |                                                                                                                                  |
| docker_stats_exporter | monitoring   |                                                                                                                                  |
| nginx_logs_exporter   | monitoring   |                                                                                                                                  |
