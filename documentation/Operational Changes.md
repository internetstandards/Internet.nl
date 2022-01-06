# Operational Changes

This document describes operational/deployment changes throughout new versions. This is intended for developers and
hosters.

## Change overview for version 1.4


### Python installation management
The makefile is 'the way to go' for running and installing the application. Inside the makefile there are a bunch
of automated procedures that supersede the manual sets from the [Installation.md](Installation.md) file. 

To setup a complete virtual environment with all needed dependencies run the following:
```bash

make venv
make unbound-37
make python-whois
make nassl
```

The results of these operations are stored in the [.venv](../.venv) directory inside this software directory.

This approach will probably change a bit in the future, but for now this is a surefire way to get a stable environment
up and running in no time.

If your environment was destroyed or something weird is happening, just `make clean` and start over.


### Python dependency management

Python dependencies are now managed with [pip-tools](https://github.com/jazzband/pip-tools/).

Dive into pip-tools and the pip-tools commands in the makefile to figure out how to upgrade dependencies. Note that, 
the manual dependencies above (unbound ...) need to be re-installed after running pip-sync. This has not yet been 
automated away due to time constraints.

The requirements.txt is now a product of pip-tools, and the high-level requirements are maintained in requirements.in.
Do not make manual changes to requirements.txt: it will land you in dependency hell.


### System Services
The [example configuration](example_configuration) folder now includes explicit separate service for daemonizing your
installation. There is a split between 'batch' and 'single' services. The single services are used for the normal
internet.nl website, while the batch services are only needed to run the batch/api deployment.

The folder structure used is explained in the [example configuration readme](example_configuration/readme.md).

Services point to the virtual environment created in the step "Python dependency management".

A new service has been added which handles the scheduler tasks (which are incompatible with gevent). Services and
their instructions are now documented in [Installation.md](Installation.md).


### Manual installation test tooling
Some simple tools have been added to check your installation. Which are:

`make manage api_check_ipv6`: performs an ipv6 test against internet.nl. This verifies that unbound is running.
`make manage api_check_rabbit`: performs a test to see if rabbitmq is correctly installed with management module.


### Changes in Django settings.py

All below changes are copied from settings.py-dist

A bunch of settings have been added:

Feature flags that disable/enable bits of the test suite:
```python
INTERNET_NL_CHECK_SUPPORT_IPV6 = bool(os.environ.get("INTERNET_NL_CHECK_SUPPORT_IPV6", True))
INTERNET_NL_CHECK_SUPPORT_DNSSEC = bool(os.environ.get("INTERNET_NL_CHECK_SUPPORT_DNSSEC", True))
INTERNET_NL_CHECK_SUPPORT_MAIL = bool(os.environ.get("INTERNET_NL_CHECK_SUPPORT_MAIL", True))
INTERNET_NL_CHECK_SUPPORT_TLS = bool(os.environ.get("INTERNET_NL_CHECK_SUPPORT_TLS", True))
INTERNET_NL_CHECK_SUPPORT_APPSECPRIV = bool(os.environ.get("INTERNET_NL_CHECK_SUPPORT_APPSECPRIV", True))
```

A logging section, configured with a dictconfig:

```python
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",  # sys.stdout
            "formatter": "color",
        },
    },
    "formatters": {
        "debug": {
            "format": "%(asctime)s\t%(levelname)-8s - %(filename)-20s:%(lineno)-4s - " "%(funcName)20s() - %(message)s",
        },
        "color": {
            "()": "colorlog.ColoredFormatter",
            # to get the name of the logger a message came from, add %(name)s.
            "format": "%(log_color)s%(asctime)s\t%(levelname)-8s - " "%(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
            "log_colors": {
                "DEBUG": "green",
                "INFO": "white",
                "WARNING": "yellow",
                "ERROR": "red",
                "CRITICAL": "bold_red",
            },
        },
    },
    "loggers": {
        # Default Django logging, we expect django to work, and therefore only show INFO messages.
        # https://docs.djangoproject.com/en/2.1/topics/logging/#django-s-logging-extensions
        "django": {
            "handlers": ["console"],
            "level": os.getenv("DJANGO_LOG_LEVEL", "INFO"),
        },
        "internetnl": {
            "handlers": ["console"],
            "level": os.getenv("DJANGO_LOG_LEVEL", "DEBUG"),
        },
        # disable verbose task logging (ie: "received task...", "...succeeded in...")
        "celery.app.trace": {
            "handlers": ["console"],
            "level": os.getenv("DJANGO_LOG_LEVEL", "DEBUG") if DEBUG else "ERROR",
        },
        "celery.worker.strategy": {
            "level": "INFO" if DEBUG else "ERROR",
        },
    },
}
```

Some routing changed for the single-app:

```python
CELERY_TASK_ROUTES = {
        'checks.tasks.dnssec.mail_callback': {'queue': 'db_worker'},
        'checks.tasks.dnssec.web_callback': {'queue': 'db_worker'},

        'checks.tasks.ipv6.mail_callback': {'queue': 'db_worker'},
        'checks.tasks.ipv6.web_callback': {'queue': 'db_worker'},

        'checks.tasks.mail.mail_callback': {'queue': 'db_worker'},

        'checks.tasks.tls.mail_callback': {'queue': 'db_worker'},
        'checks.tasks.tls.web_callback': {'queue': 'db_worker'},

        'checks.tasks.appsecpriv.web_callback': {'queue': 'db_worker'},

        'interface.views.shared.run_stats_queries': {'queue': 'slow_db_worker'},
        'interface.views.shared.update_running_status': {'queue': 'slow_db_worker'},
        'checks.tasks.update.update_hof': {'queue': 'slow_db_worker'},
}
```

Routing has changed for the batch instance:

```python
CELERY_BATCH_TASK_ROUTES = {
        'checks.tasks.dnssec.batch_mail_callback': {'queue': 'batch_callback'},
        'checks.tasks.dnssec.batch_mail_is_secure': {'queue': 'batch_main'},
        'checks.tasks.dnssec.batch_web_callback': {'queue': 'batch_callback'},
        'checks.tasks.dnssec.batch_web_is_secure': {'queue': 'batch_main'},

        'checks.tasks.ipv6.batch_mail_callback': {'queue': 'batch_callback'},
        'checks.tasks.ipv6.batch_mx': {'queue': 'batch_main'},
        'checks.tasks.ipv6.batch_ns': {'queue': 'batch_main'},
        'checks.tasks.ipv6.batch_web': {'queue': 'batch_main'},
        'checks.tasks.ipv6.batch_web_callback': {'queue': 'batch_callback'},

        'checks.tasks.mail.batch_dkim': {'queue': 'batch_main'},
        'checks.tasks.mail.batch_dmarc': {'queue': 'batch_main'},
        'checks.tasks.mail.batch_mail_callback': {'queue': 'batch_callback'},
        'checks.tasks.mail.batch_spf': {'queue': 'batch_main'},

        'checks.tasks.shared.batch_mail_get_servers': {'queue': 'batch_main'},
        'checks.tasks.shared.batch_resolve_a_aaaa': {'queue': 'batch_main'},

        'checks.tasks.tls.batch_mail_callback': {'queue': 'batch_callback'},
        'checks.tasks.tls.batch_mail_smtp_starttls': {'queue': 'batch_main'},
        'checks.tasks.tls.batch_web_callback': {'queue': 'batch_callback'},
        'checks.tasks.tls.batch_web_cert': {'queue': 'batch_main'},
        'checks.tasks.tls.batch_web_conn': {'queue': 'batch_main'},
        'checks.tasks.tls.batch_web_http': {'queue': 'batch_main'},

        'checks.tasks.appsecpriv.batch_web_appsecpriv': {'queue': 'batch_main'},
        'checks.tasks.appsecpriv.batch_web_callback': {'queue': 'batch_callback'},

        'interface.batch.util.batch_async_generate_results': {'queue': 'batch_slow'},
        'interface.batch.util.batch_async_register': {'queue': 'batch_slow'},

        'interface.batch.scheduler.run': {'queue': 'batch_scheduler'},
    }
```


And celery imports have changed:

```python
CELERY_IMPORTS = (
    'checks.tasks.update',
    'interface.batch.scheduler',
    'interface.batch.util',
)
```



Some more options can be controlled using environment variables:
```python
DEBUG = bool(os.environ.get("DEBUG", False))

ENABLE_BATCH = bool(os.environ.get("ENABLE_BATCH", False))
```




Database settings from the environment, making way for deployment using environment variables.
Also including some commands to get a development psql service working.

```python
"""
PSQL settings for development purposes (no db restrictions for this user):
This creates the standard development database ('internetnl') and one for test: test_internetnl

create database internetnl;
create role internetnluser with password 'internetnluser';
grant connect on database internetnl to internetnluser;
grant all on database internetnl to internetnluser;
alter role internetnluser login;

create database test_internetnl;
grant connect on database test_internetnl to internetnluser;
grant all on database test_internetnl to internetnluser;

GRANT ALL ON ALL TABLES IN SCHEMA public to internetnluser;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public to internetnluser;
GRANT ALL ON ALL FUNCTIONS IN SCHEMA public to internetnluser;
ALTER USER internetnluser CREATEDB;
"""
DATABASES_SETTINGS = {
    "dev": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": os.environ.get("DB_NAME", "db.sqlite3"),
    },
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': os.environ.get("DB_NAME", "internetnl"),
        'USER': os.environ.get("DB_USER", "internetnluser"),
        'PASSWORD': os.environ.get("DB_PASSWORD", "internetnluser"),
        'HOST': os.environ.get("DB_HOST", '127.0.0.1')
    }
}

# For development, use dev in your own settings.py:
DATABASE = os.environ.get("DJANGO_DATABASE", "default")
DATABASES = {"default": DATABASES_SETTINGS[DATABASE]}
```


Templates are now explicitly mentioned and parser functions are explicitly listed:

```python
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': ['', 'interface', 'interface/templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                "django.contrib.auth.context_processors.auth",
                "django.template.context_processors.debug",
                "django.template.context_processors.i18n",
                "django.template.context_processors.media",
                "django.template.context_processors.static",
                "django.template.context_processors.tz",
                "django.contrib.messages.context_processors.messages",
                "django.template.context_processors.request",
            ],
            'libraries': {
                'translate': 'interface.templatetags.translate'
            }
        },
    },
]
```

Apps are split, changing INSTALLED_APPS:

```python
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django_bleach',
    'markdown_deux',
    'frontend',
    'interface',
    'checks',
    'django_hosts',
]
```


### Changes in testing 
You can run `make test` to run the test suite and see the coverage. Run `make tescase case=...` to run a specific testcase.
These testcases should be placed in the 'test' folder in each Django application. New developments are expected to come
with testcases.

Testing is configured in setup.cfg. The test suite outputs an extensive report in the command line, showing where
tests need to be added. At the time of writing test coverage is at 38%, which is a source of risk and bugs.

A test for registering a batch scan has been added as an example.
