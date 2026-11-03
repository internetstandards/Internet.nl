# Docker container profiles overview

This overview was last generated with `make update_container_documentation`.


| container             | profiles                              | description                                                                                                                            |
|-----------------------|---------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------|
| webserver             |                                       | nginx proxy container, also runs certbot                                                                                               |
| app                   |                                       | django container                                                                                                                       |
| db-migrate            |                                       | django DB migrations, runs to completion and exits with 0                                                                              |
| worker                |                                       |                                                                                                                                        |
| worker-nassl          |                                       | worker for queue with potential memory leak                                                                                            |
| worker-slow           |                                       | worker for slow and long running tasks that could require a lot of memory (eg: hof update)                                             |
| worker-scheduler      |                                       | prefork worker for batch scheduling. Avoids issue https://github.com/internetstandards/Internet.nl/pull/2106 after switching to gevent |
| beat                  |                                       | celery task queue                                                                                                                      |
| redis                 |                                       | redis caches state, also used for:<br>- MAC address lookup<br>- Django page cache<br>- client DNS resolver IPs in connectiontest       |
| rabbitmq              |                                       | rabbitmq message-broker                                                                                                                |
| postgres              |                                       | database                                                                                                                               |
| routinator            | routinator                            | for RPKI                                                                                                                               |
| unbound               |                                       | unbound DNS server used for connection test                                                                                            |
| resolver-validating   |                                       | unbound resolver used for ldns-dane that require DNSSEC validation                                                                     |
| cron                  |                                       | cron with periodic tasks                                                                                                               |
| cron-docker           |                                       | cron daemon with access to Docker socket but no networking                                                                             |
| grafana               | monitoring                            |                                                                                                                                        |
| prometheus            | monitoring                            |                                                                                                                                        |
| alertmanager          | alertmanager                          | requires monitoring profile                                                                                                            |
| postgresql-exporter   | monitoring, monitoring-exporters-only |                                                                                                                                        |
| redis-exporter        | monitoring, monitoring-exporters-only |                                                                                                                                        |
| statsd-exporter       | monitoring, monitoring-exporters-only |                                                                                                                                        |
| celery-exporter       | monitoring, monitoring-exporters-only |                                                                                                                                        |
| node-exporter         | monitoring, monitoring-exporters-only |                                                                                                                                        |
| docker_stats_exporter | monitoring, monitoring-exporters-only |                                                                                                                                        |
| nginx_logs_exporter   | monitoring, monitoring-exporters-only |                                                                                                                                        |
| query-exporter        | monitoring, monitoring-exporters-only |                                                                                                                                        |
