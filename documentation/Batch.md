# Batch functionality

The Internet.nl codebase is bundled with batch functionality, that is the
ability to submit a number of domains at once for web or email testing.

This is accomplished through a REST API.

## Information for operators

### Enabling the API
1. Change the `ENABLE_BATCH` value in `internetnl/settings.py` to `True`.

2. The `BATCH_TEST_USER` is only meant for initial debugging (the user still
   needs to be created; look below) and is not to be used in a production
   environment.

3. Make sure that `CELERY_ROUTES` are only defined once in the file. The
   default values that come in the batch section allow for a more fine grained
   celery routing and are recommended for the constant volume of tasks.
   Of course you would need to change your celery configuration (nodes, queues)
   accordingly.

4. Make sure that the management plugin is available and enabled on your
   rabbitMQ installation.

### Generating the documentation
The API follows the [OpenAPI specification](https://swagger.io/specification/).

Copy `internetnl/batch_api_doc_conf.py-dist` to
`internetnl/batch_api_doc_conf.py` and change any appropriate settings to your
liking.

Run `manage.py api_generate_doc` to generate the documentation. You
can then visit `/api/batch/openapi.yaml` to get the documentation (also
available in the `static` folder locally). **The documentation needs to be
regenerated whenever anything changes in the API specification
(`checks/batch/openapi.yaml`)**

### Users
Any activity on the batch functionality requires a configured user.

Authorization of the users is not done by the Django application itself but
rather relies on the upfront webserver to do the necessary HTTP Auth and pass
the authenticated user to the Django application.

The `manage.py api_users` command helps with managing user information on the
Django application.

Management for the HTTP authenticated users needs to happen separately for the
upfront webserver.

### Forwarding resolver
In batch operation mode it is advised to use a forwarding resolver that all the
celery tasks are going to forward DNS queries to. This is configurable with the
`CENTRAL_UNBOUND` option.

### DB indexes
When running in batch operation mode it is advised to run
`manage.py api_create_db_indexes`. This creates additional DB indexes needed
for the batch functionality.


## Information for developers

The batch functionality is a wrapper around the Internet.nl main functionality
with some added tables to keep track of batch_[users|requests|tests] and some
logic to submit normal tests to the main Internet.nl functionality.

### Logic

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
  Stores the registered users; not passwords.
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
