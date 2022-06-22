# Overview

Internet.nl is a complex project, both the codebase itself, and the
requirements to deploy it.
To start, read the [architecture overview](architecture.md) to understand the
various components and how they interact.

Internet.nl is fundamentally a [Django](https://www.djangoproject.com/)
based application. Current install base is Django 3.2 with Python 3.7.

To run the project, there are a few options:

* [Running with Docker](https://github.com/internetstandards/Internet.nl/blob/main/docker/README.md).
  Simplest install, only supported on Linux hosts.
  **Not confirmed to work as of May 2022**.
* A [typical local installation for development](development.md).
  **Status on M1 mac unclear**.
* A [full install on a server](Installation.md).

Note that the connection test requires a lot more moving parts than the other
tests, as it handles inbound connections.

Other important resources:

* [How to customize your installation](Customize.md)
* [Batch functionality](Batch.md)
* [Operational Changes](Operational%20Changes.md)
* [Historic overview on scoring](scores.md)
* More generic [deployment instructions](/Deployment.md)
