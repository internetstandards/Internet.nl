# Deployment

_The deployment instructions described here are mostly generic. Specific
instructions are not given because they rely heavily on the preferred chosen
environment of one's installation._

When deploying make sure to follow these steps on your local environment and
push the changes to the server:

1. If there was a change in the frontend (CSS or javascript) run the following:
   ```
   make frontend
   ```

2. _Periodically_ update needed remote data with:
   ```
   make update_cert_fingerprints
   make update_padded_macs
   make update_root_key_file
   ```
   This is already done with each release, but in case you are not using the
   latest release. For the update_cert_fingerprints, please read issue #614
   
On the server you need to:

1. Create the latest translation files and compile them:
   ```
   make translations
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
