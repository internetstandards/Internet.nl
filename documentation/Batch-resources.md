# Tested systems and results

## System

    Hosts: docker.batch.internet.nl, dev-docker.batch.internet.nl
    CPU: 4x Xeon 2.4Ghz
    Memory: 16GB
    Settings: https://github.com/internetstandards/Internet.nl/blob/workerqueues/docker/defaults.env

  ## Runs

    Batch: 10k top tranco web
    Host: dev-docker.batch.internet.nl
    Version: 1.8.5.dev98-g44debe4 (commit 44debe4922b641f55c767428727fc37e74d2355e)
    Worker concurrency: 500
    Batch scheduler interval: 5s
    Runtime: ~1 hour
    Throughput: ~166/min
    System top memory usage: ~9GB (note, 36 workers)
    System cpu load: ~75%
    Metrics: https://dev-docker.batch.internet.nl/grafana/d/bdd9dac3-b85a-4420-8158-bd92e06da08d/batch?orgId=1&from=1719399426043&to=1719411943563
    Notes: separate queues/workers per batch task, meaning 36 workers, there is a delay between finishing the scans and starting the generation of results.


    Batch: 5k top tranco web
    Host: dev-docker.batch.internet.nl
    Worker concurrency: 500
    Batch scheduler interval: 1s
    Runtime: ~45 minutes (30 minutes running tests, 12 minutes waiting for result generation, 2-3 minutes generating results)
    Throughput: ~166/min
    System top memory usage: ~3GB
    System cpu load: ~60%
    Metrics: https://dev-docker.batch.internet.nl/grafana/d/bdd9dac3-b85a-4420-8158-bd92e06da08d/batch?orgId=1&from=1719907118233&to=1719910016716
    Notes: there is a delay between finishing the scans and starting the generation of results.


    Batch: 2x 5k top tranco web (concurrent)
    Host: dev-docker.batch.internet.nl
    Worker concurrency: 500
    Batch scheduler interval: 1s
    Runtime: ~1 hour total, job 1 ~40minutes, job 2 57 minutes.
    Throughput: ~166/min
    System top memory usage: ~3.5GB
    System cpu load: ~30-60%
    Metrics: https://dev-docker.batch.internet.nl/grafana/d/bdd9dac3-b85a-4420-8158-bd92e06da08d/batch?orgId=1&from=1719910577776&to=1719914165252
    Notes: there is a delay between finishing the scans and starting the generation of results.


    Batch: 20k top tranco web
    Host: dev-docker.batch.internet.nl
    Worker concurrency: 500
    Batch scheduler interval: 1s
    Runtime: ~2 hours
    Throughput: ~166/min
    System top memory usage: ~6GB (3GB during scan, +3GB during report generation)
    System cpu load: ~65%
    Metrics: https://dev-docker.batch.internet.nl/grafana/d/bdd9dac3-b85a-4420-8158-bd92e06da08d/batch?orgId=1&from=1719917139205&to=1719928635564
    Notes: report generation retried after first time was OOM killed due to container having to little memory


    Batch: 5k top tranco web
    Host: docker.batch.internet.nl
    Worker concurrency: 500
    Batch scheduler interval: 1s
    Runtime: ~45 minutes (30 minutes running tests, 12 minutes waiting for result generation, 2-3 minutes generating results)
    Throughput: ~166/min
    System top memory usage: ~3.3GB
    System cpu load: ~60%
    Metrics: https://docker.batch.internet.nl/grafana/d/bdd9dac3-b85a-4420-8158-bd92e06da08d/batch?orgId=1&from=1719917714000&to=1719920714000


    Batch: 2x 10k top tranco web (concurrent)
    Host: docker.batch.internet.nl
    Worker concurrency: 500
    Batch scheduler interval: 1s
    Runtime: ~1h51m, (first batch 1h23m, second 1h51m)
    Throughput: ~180/m
    System top memory usage: 4.4GB
    System cpu load: ~60-70%
    Metrics: https://docker.batch.internet.nl/grafana/d/bdd9dac3-b85a-4420-8158-bd92e06da08d/batch?orgId=1&from=1719923089190&to=1719930142051


    Batch: 5k top tranco mail
    Host: dev-docker.batch.internet.nl
    Worker concurrency: 500
    Batch scheduler interval: 1s
    Runtime: 1h
    Throughput: ~83/min
    System top memory usage: 6.2GB (mainly due to previous batch request's report generate)
    System cpu load: ~45%
    Metrics: https://dev-docker.batch.internet.nl/grafana/d/bdd9dac3-b85a-4420-8158-bd92e06da08d/batch?orgId=1&from=1719929106000&to=1719932864425


    Batch: 5k top tranco web
    Host: docker.batch.internet.nl
    Worker concurrency: 500 (2 main workers)
    Batch scheduler interval: 1s
    Runtime: 39m (~30m scanning, ~8m waiting for generate to start, ~1m generate report)
    Throughput: 130/min (166/min scanning)
    System top memory usage: 4GB
    System cpu load: 90%
    Metrics: https://docker.batch.internet.nl/grafana/d/bdd9dac3-b85a-4420-8158-bd92e06da08d/batch?orgId=1&from=1719930330977&to=1719932806197


    Batch: 5x 5k top tranco web (concurrent)
    Host: dev-docker.batch.internet.nl
    Worker concurrency: 500 (2 main workers)
    Batch scheduler interval: 1s
    Runtime: 1h39m (44m, 54m, 1h09m, 1h24m, 1h39m from start of each respective batch request)
    Throughput: 252/min
    System top memory usage: ~4.9GB
    System cpu load: 90%/45%
    Metrics: https://docker.batch.internet.nl/grafana/d/bdd9dac3-b85a-4420-8158-bd92e06da08d/batch?orgId=1&from=1719933290000&to=1719940681081
    Notes: after the first of the 5 batch runs has completed the rest of the runs seem to not run as efficient, using only half of the CPU compared to the first and about 1/3rd of the throughput regarding tasks. The same domain list was used for each requests, so caching might be in play here regarding resource usage and throughput.


    Batch: 'tranco 5000 web' from acc.dashboard.internet.nl
    Host: dev-docker.batch.internet.nl
    Worker concurrency: 500
    Batch scheduler interval: 1s
    Runtime: 38m
    Throughput: ~130/min
    System top memory usage: 4.8GB
    System cpu load: 60%
    Metrics: https://dev-docker.batch.internet.nl/grafana/d/bdd9dac3-b85a-4420-8158-bd92e06da08d/batch?orgId=1&from=1720000132804&to=1720003146920

    Batch: 'Frontpage Tranco Top 1000 NL Domains' web and mail, 'internet.nl domain tests' web and mail from acc.dashboard.internet.nl (concurrent)
    Host: dev-docker.batch.internet.nl
    Worker concurrency: 500
    Batch scheduler interval: 1s
    Runtime: stalled after 16 minutes
    Throughput: n/a
    System top memory usage: 4.9GB
    System cpu load: 40-50%
    Metrics: https://dev-docker.batch.internet.nl/grafana/d/bdd9dac3-b85a-4420-8158-bd92e06da08d/batch?orgId=1&from=1720005643730&to=1720008617826
    Notes: after 23 minutes


# Tunables

### Worker containers (`WORKER_REPLICAS`)

Workers use greenlets for threads, meaning they use only 1 CPU. By deploying multiple worker containers load is spread across multiple CPUs/cores.

Recommended: `2` (or nr. of CPUs/cores)

Setting this to low will result in underutilisation of CPU resources. Setting this to high will not result in better throughput and just waste memory resources.

### Worker concurrency (`WORKER_CONCURRENCY`):

Number of concurrent threads (greenlets) for the 'normal' and 'nassl' worker, 'slow' worker has it's own concurrency setting and is set very low to prevent memory overusage on report generation.

Recommended: `500`

Setting this to low will result in low throughput of tests. Setting this to high will result in errors due to too many open files.

### Batch scheduler interval (`BATCH_SCHEDULER_INTERVAL`):

Batch tests are started by the batch scheduler 'run' task which it started every `BATCH_SCHEDULER_INTERVAL` time interval. This tasks has internal locking and will prevent duplicates from executing. If the task is finished new tests won't be started until the next time interval.

Recommended: `1s`

Settings this to high will result in periods when no tests are performed and thus lower throughput. There is no downside of setting this value very low.

### Batch schedule domains (`BATCH_SCHEDULER_DOMAINS`)

Amount of domains that test are started by the 'run' task (see above). No extensive testing has been done yet on the effect of this value.

Recommended: `25` (default, currently not configurable)

### Postgresql DB connections

Some 3rd party suggest increasing the PostgreSQL DB connection, but our current metrics indicated only about 10% of the current 100 connections are in use at a time: https://dev-docker.batch.internet.nl/grafana/d/wGgaPlciz/postgres-overview?orgId=1&viewPanel=13&from=1718559849685&to=1719911540873&editPanel=13

Recommended: 100 (PostgreSQL default, currently not configurable)

### Redis connections

Similar to PostgreSQL, current metrics don't suggest there is a need to increase this value: https://dev-docker.batch.internet.nl/grafana/d/bRd48yKMdd/redis-dashboard-for-prometheus-redis-exporter-1-x?orgId=1&viewPanel=16&from=1718523798829&to=1719911583532

Recommended: 10000 (Redis default, currently not configurable)

# Useful commands

Get status and runtime of top 10 batch jobs from DB:

    docker exec -ti internetnl-prod-postgres-1 psql --username "internetnl" --dbname "internetnl_db1" -c 'select name, status, request_id, submit_date, finished_date, finished_date - submit_date as runtime from checks_batchrequest order by submit_date desc limit 10'

See if there are locks in Redis for result generation or scheduler:

    docker exec -ti internetnl-prod-redis-1 redis-cli keys \*:lock:\*
    docker exec -ti internetnl-prod-redis-1 redis-cli keys \*:gen:\*

Delete a pending lock by running:

    docker exec -ti internetnl-prod-redis-1 redis-cli del ":1:batch:results:gen:example.user:cc1a2d433e66436cbc542913e30b7147"

Cancel all currently running or pending batch requests:

    docker exec -ti internetnl-prod-postgres-1 psql --username "internetnl" --dbname "internetnl_db1" -c 'update checks_batchrequest set status = 39 where status = 11 or status = 10;'
