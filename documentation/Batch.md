# Batch functionality

The Internet.nl codebase is bundled with batch functionality, that is the
ability to submit a number of domains at once for web or email testing.

This is accomplished through a REST API.
The API documentation of the Internet.nl API v2.0 can be found on https://batch.internet.nl/api/batch/openapi.yaml.
A viewer, like ReDoc, can be used for generating a human readable version: http://redocly.github.io/redoc/?url=https://batch.internet.nl/api/batch/openapi.yaml.

Examples of API consumer scripts:
- Internet.nl Dashboard: https://github.com/internetstandards/Internet.nl-dashboard
- Internet.nl batch scripts: https://github.com/poorting/internet.nl_batch_scripts

## Deploying a batch instance
See [Deployment Batch](Docker-deployment-batch.md).

## Users
Any activity on the batch functionality requires a configured user.

Authorization of the users is not done by the Django application itself but
rather relies on the upfront webserver to do the necessary HTTP Auth and pass
the authenticated user to the Django application. The known users can be
managed with the `/opt/Internet.nl/docker/batch_user.sh` script, detailed
in the batch deployment documentation.

## Overview of significant differences in batch mode

* The connection test is not available.
* DNSSEC tests do not perform a registrar lookup.
* The REST API is only enabled in batch mode.
* The hall of fame is not enabled.
* Individual clients are not rate limited, as scheduling is entirely different as explained below.
* No prechecks are performed e.g. to check whether the hostname has an A/AAAA record.
* The database has some additional indexes.

These configuration differences are automatically managed by the deployment based on `ENABLE_BATCH`,
or is documented in the batch deployment guide.

## Information for developers

The batch functionality is a wrapper around the Internet.nl main functionality
with some added tables to keep track of batch_[users|requests|tests] and some
logic to submit normal tests to the main Internet.nl functionality.

### Logic

Fundamentally:
- Batch requests are processed on a FIFO basis for a particular user. This means a users can submit multiple batch requests, but they are processed sequentally. The first / current batch requests needs to finish before the next one starts. 
- Batch requests of multiple users are run in parallel. While influenced by the number of users running simultaneous batch requests, you should assume that parallel tasks take longer to finish since server resources are being shared. 

All the batch logic is being ran/managed by `checks/batch/scheduler.py` which
is ran periodically in celery and in short:
1. Does some bookkeeping for stalled tests;
2. Updates the statuses of user batch requests based on the statuses of the
   relevant tests;
3. If the task queue is not considered full:
   a. Picks an ongoing batch request randomly among all the users;
   b. Submits the relevant test for the domain if there are no recent results
      (results gotten after the batch request's submission date) that could be
      used straight away (in case more than one user tests the same domains);
   c. Repeats until a configurable amount of domains is submitted per run.

### Relevant DB Models

- `BatchUser`
  Stores the registered users; not passwords. Automatically created.
- `BatchRequest`
  Stores the batch requests that come through the API along with links to the
  generated result files.
- `BatchDomain`
  Stores the domains to be tested per request. These map to one of the
  following tables based on the request type (web or mail).
- `BatchWebTest` and `BatchMailTest`
  Store mappings and statuses to the core test tables. This is where the
  wrapping of batch over core Internet.nl happens in action.
  These tables need to be updated when a new test category (e.g., appsecpriv)
  is introduced as they need to map to the relevant test table.

### Introducing new tests on an existing test category

By introducing new tests (DB fields) on an existing test category (DB table)
the following updates need to happen in relation to the batch functionality:
1. Update `checks/models.py`. Apart from the changes to the table, certain
   methods like `get_web_api_details()` will need extra information to generate
   batch technical results;
2. Update `checks/batch/openapi.yaml`, especially for the technical results
   part;
3. Update `checks/batch/__init__.py`; don't forget the version, it should at
   least bump the minor version;
4. Update `checks/batch/util.py`. Based on which test was updated you may need
   to update parts of the functions that gather results.

### Introducing new test category

By introducing a new test category (DB table) the following updates need to
happen in relation to the batch functionality:
0. All of the above updates to the files including further updates for the new
   test category;
1. Update `checks/probes.py` to include probes for the new test category;
2. Update `checks/batch/scheduler.py` for the new test category.
