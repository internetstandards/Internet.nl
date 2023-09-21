# Overview

Internet.nl is a complex project, both the codebase itself, and the
requirements to deploy it.
To start, read the [architecture overview](architecture.md) to understand the
various components and how they interact.

Internet.nl is fundamentally a [Django](https://www.djangoproject.com/)
based application, developed/tested/deployed through Docker containers.

- [Getting started](Docker-getting-started.md)
- [Architecture](Docker-architecture.md)
- [Development Environment](Docker-development-environment.md)
- [Integration tests](Docker-integration-tests.md)
- [Deployment](Docker-deployment.md)
- [Deployment Batch](Docker-deployment-batch.md)
- [Live tests](Docker-live-tests.md)
- [Metrics](Docker-metrics.md)


Note that the connection test requires more moving parts than the other
tests, as it handles inbound connections.

Other important resources:

* [How to customize your installation](Customize.md)
* [Batch functionality](Batch.md)
* [Operational Changes](Operational%20Changes.md)
* [Historic overview on scoring](scores.md)
* More generic [deployment instructions](/Deployment.md)

Documentation for specific test areas:

* [RPKI test](rpki.md)
