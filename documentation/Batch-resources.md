This document details the CPU and memory requirements for batch runs.

Host: dev-docker.batch.internet.nl
CPU: 4x Xeon 2.4Ghz
Memory: 16GB
Version: 1.8.5.dev98-g44debe4 (commit 44debe4922b641f55c767428727fc37e74d2355e)
Settings: https://github.com/internetstandards/Internet.nl/blob/workerqueues/docker/defaults.env
Worker concurrency: 500
Batch scheduler interval: 5s
Notes: separate queues/workers per batch task, meaning 36 workers

Batch: 10k top tranco web
Runtime: ~1 hour
Throughput: ~150/min
System top memory usage: ~9GB (note, 36 workers)
System cpu load: ~75%
Dashboard: https://dev-docker.batch.internet.nl/grafana/d/bdd9dac3-b85a-4420-8158-bd92e06da08d/batch?orgId=1&from=1719399426043&to=1719411943563



Tunables:

concurrency - meh, te weinig is niet goed, te veel voegt niet meer toe
scheduler interval - te hoog en de helft van de tijd staan de workers niks te doen
db connections - doet heel weinig, gemiddeld wordt slechts 10% van de 100 default connections gebruikt
redis connections - idem, niet relevant
