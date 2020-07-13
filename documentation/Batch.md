# Batch functionality

The internet.nl codebase is bundled with batch functionality, that is the
ability to submit a number of domains at once for web or email testing.

This is accomplished through a REST API.

## Enabling the API
1. Change the `ENABLE_BATCH` value in `internetnl/settings.py` to `True`.

2. The `BATCH_TEST_USER` is only meant for initial debuging (the user still
   needs to be created; look below) and is not to be used in a production
   environment.

3. Make sure that `CELERY_ROUTES` are only defined once in the file. The
   default values that come in the batch section allow for a more fine grained
   celery routing and are recommended for the constant volume of tasks.
   Ofcourse you would need to change your celery configuration (nodes, queues)
   accordingly.

4. Make sure that the management plugin is available and enabled on your
   rabbitMQ installation.

## Generating the documentation
The API follows the [OpenAPI specification](https://swagger.io/specification/).

Copy `internetnl/batch_api_doc_conf.py-dist` to
`internetnl/batch_api_doc_conf.py` and change any appropriate settings to your
liking.

Run `manage.py api_generate_doc` to generate the documentation. You
can then visit `/api/batch/openapi.yaml` to get the documentation (also
available in the `static` folder locally).

## Users
Any activity on the batch functionality requires a configured user.

Authorization of the users is not done by the django application itself but
rather relies on the upfront webserver to do the necessary HTTP Auth and pass
the authenticated user to the django application.

The `manage.py api_users` command helps with managing user information on the
django application.

Management for the HTTP authenticated users needs to happen separately for the
upfront webserver.

## Forwarding resolver
In batch operation mode it is advised to use a forwarding resolver that all the
celery tasks are going to forward DNS queries to. This is configurable with the
`CENTRAL_UNBOUND` option.

## DB indexes
When running in batch operation mode it is advised to run
`manage.py api_create_db_indexes`. This creates additional DB indexes needed
for the batch functionality.
