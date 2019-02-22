# Deployment

_The deployment intructions described here are mostly generic. Specific
instructions are not given because they rely heavily on the preferred chosen
environment of one's installation._

When deploying make sure to follow these steps on your local environment and
pushthe changes to the server:

1. If there was a change in the frontend run the following where applicable:
   ```
   make frontend css
   make frontend js
   ```

2. Periodically update needed remote data with:
   ```
   make update_cert_fingerprints
   make update_padded_macs
   make update_root_key_file
   ```
On the server you need to:

1. Make sure that you have the latest translation files compiled:
   ```
   cd checks; python ../manage.py compilemessages; cd ..
   ```

2. Collected all the static files to `static/` so that they are ready to be
   served by the webserver:
   ```
   python ./manage.py collectstatic
   ```

3. Make sure that redis, postgresql and rabbitmq are up and running.


## Local deployment

1. Start/restart celery and django for local development.


## Production deployment

0. Make sure that your configuration has DEBUG disabled in `internet.nl/settings.py`

1. Make sure to restart the celery process in order to load the new code.

2. Restart/reload your webserver (relies on your configuration and selection of
   apache/ngingx along with wsgi/gunicorn)
