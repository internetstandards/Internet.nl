"""
Django settings for internetnl project.

For more information on this file, see
https://docs.djangoproject.com/en/3.0/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/3.0/ref/settings/

Note that the most important settings, which commonly change, can also be set using the environment.
For an example, see internet.nl.dist.env.
"""

import os
from os import getenv
import socket
import sentry_sdk

from internetnl.settings_utils import (
    split_csv_trim,
    BASE_DIR,
    get_boolean_env,
    remove_sentry_pii,
)
from setuptools_scm import get_version
from django.core.management.utils import get_random_secret_key


# Infrastructure
# # Generic / Django Framework
# # SECURITY WARNING: don't run with debug turned on in production!
DEBUG = get_boolean_env("DEBUG", False)
# enable debug logging specifically or follow DEBUG value
DEBUG_LOG = get_boolean_env("DEBUG_LOG", DEBUG)
DEBUG_LOG_UNBOUND = get_boolean_env("DEBUG_LOG_UNBOUND", False)

# SECURITY WARNING: keep the secret key used in production secret!
GENERATE_SECRET_KEY = get_boolean_env("GENERATE_SECRET_KEY", False)
if GENERATE_SECRET_KEY:
    SECRET_KEY = get_random_secret_key()
else:
    SECRET_KEY = getenv("SECRET_KEY", "secret")
SKIP_SECRET_KEY_CHECK = bool(getenv("SKIP_SECRET_KEY_CHECK", DEBUG))

# # If Django is proxied (eg. webserver proxying to django/uwsgi) enable this setting.
# # Make sure that the `X-Forwarded-For` and `X-Forwarded-Proto` HTTP headers;
# # and the option to Preserve the Host are set by your proxy.
DJANGO_IS_PROXIED = get_boolean_env("DJANGO_IS_PROXIED", False)
ALLOWED_HOSTS = split_csv_trim(getenv("ALLOWED_HOSTS", ".internet.nl, internet.nl"))
INTERNAL_IPS = split_csv_trim(getenv("INTERNAL_IPS", ""))
TIME_ZONE = getenv("TIME_ZONE", "UTC")

# Infrastructure
# # Application logging:
DJANGO_LOG_LEVEL = getenv("DJANGO_LOG_LEVEL", "INFO")
INTERNETNL_LOG_LEVEL = getenv("INTERNETNL_LOG_LEVEL", "INFO")
CELERY_LOG_LEVEL = getenv("CELERY_LOG_LEVEL", "ERROR")

# Infrastructure
# # Database
DJANGO_DATABASE = getenv("DJANGO_DATABASE", "default")
DB_NAME = getenv("DB_NAME", "internetnl")
DB_USER = getenv("DB_USER", "internetnluser")
DB_PASSWORD = getenv("DB_PASSWORD", "secret")
DB_HOST = getenv("DB_HOST", "127.0.0.1")
DB_PORT = int(getenv("DB_PORT", 5432))

# Infrastructure
# # Celery
CELERY_BROKER_URL = getenv("CELERY_BROKER_URL", "amqp://guest@localhost//")
CELERY_RESULT_BACKEND = getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/0")

# Infrastructure
# # Redis Cache
CACHE_LOCATION = getenv("CACHE_LOCATION", "redis://localhost:6379/0")
CACHE_ENABLED = bool(CACHE_LOCATION)

# Infrastructure
# # LDNS Dane / or ldns-dane-wrapper ('./ldns-dane-wrapper')
LDNS_DANE = getenv("LDNS_DANE", "/usr/local/bin/ldns-dane")

# Features
# # Site
MANUAL_HOF_PAGES = split_csv_trim(getenv("MANUAL_HOF_PAGES", ""))
HAS_ACCESSIBILITY_PAGE = get_boolean_env("HAS_ACCESSIBILITY_PAGE", True)

# Features
# # Scanning
# # Used for scanning as well as allowed hosts, use for example your own server IP address:
IPV6_TEST_ADDR = getenv("IPV6_TEST_ADDR", "::1")
CONN_TEST_DOMAIN = getenv("CONN_TEST_DOMAIN", "internet.nl")
SMTP_EHLO_DOMAIN = getenv("SMTP_EHLO_DOMAIN", "internet.nl")  # MUST be ASCII; A-label for IDNs (i.e., xn--)

# Features
# # Checks
# # The following flags enable and disable various parts of the checks. This allows for faster, more targeted scanning.
INTERNET_NL_CHECK_SUPPORT_IPV6 = get_boolean_env("INTERNET_NL_CHECK_SUPPORT_IPV6", True)
INTERNET_NL_CHECK_SUPPORT_DNSSEC = get_boolean_env("INTERNET_NL_CHECK_SUPPORT_DNSSEC", True)
INTERNET_NL_CHECK_SUPPORT_MAIL = get_boolean_env("INTERNET_NL_CHECK_SUPPORT_MAIL", True)
INTERNET_NL_CHECK_SUPPORT_TLS = get_boolean_env("INTERNET_NL_CHECK_SUPPORT_TLS", True)
INTERNET_NL_CHECK_SUPPORT_APPSECPRIV = get_boolean_env("INTERNET_NL_CHECK_SUPPORT_APPSECPRIV", True)
INTERNET_NL_CHECK_SUPPORT_RPKI = get_boolean_env("INTERNET_NL_CHECK_SUPPORT_RPKI", True)

# Features
# # User Tracking
MATOMO_URL = getenv("MATOMO_URL", "//matomo.internet.nl/")
MATOMO_SITEID = int(getenv("MATOMO_SITEID", "1"))
# # Used for subdomain tracking eg. *.internet.nl
MATOMO_SUBDOMAIN_TRACKING = getenv("MATOMO_SUBDOMAIN_TRACKING", "")

# Features
# # Batch support
ENABLE_BATCH = get_boolean_env("ENABLE_BATCH", False)
RABBIT_HOST = getenv("RABBIT_HOST", "localhost:15672")  # Note: Management port
RABBIT_USER = getenv("RABBIT_USER", "guest")
RABBIT_PASS = getenv("RABBIT_PASS", "guest")

ENABLE_HOF = get_boolean_env("ENABLE_HOF", True)

AUTORELOAD = get_boolean_env("INTERNETNL_AUTORELOAD", False)

# -- End of manual configuration

"""
Do not edit below this line, unless you know what you are doing.
Settings below are application/django settings that are intended to be generic for each installation.
"""

if ENABLE_BATCH:
    print("Batch enabled.")
else:
    print("Single domain scan enabled, batch scanning and API not available.")

ALLOWED_HOSTS = ALLOWED_HOSTS + [IPV6_TEST_ADDR, f"[{IPV6_TEST_ADDR}]"]

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.staticfiles",
    "django_bleach",
    "markdown_deux",
    "interface",
    "checks",
    "django_hosts",
    "django_statsd",
]
if AUTORELOAD:
    INSTALLED_APPS += ["django_browser_reload"]

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": ["", "interface", "interface/templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.i18n",
                "django.template.context_processors.media",
                "django.template.context_processors.static",
                "django.template.context_processors.tz",
                "django.template.context_processors.request",
            ],
            "libraries": {"translate": "interface.templatetags.translate"},
        },
    },
]

LOCALE_PATHS = ["locale"]

MIDDLEWARE = [
    # serves static files in production
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django_statsd.middleware.GraphiteRequestTimingMiddleware",
    "django_statsd.middleware.GraphiteMiddleware",
    "django_hosts.middleware.HostsRequestMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django_hosts.middleware.HostsResponseMiddleware",
    "internetnl.custom_middlewares.ActivateTranslationMiddleware",
]
if AUTORELOAD:
    MIDDLEWARE += [
        "django_browser_reload.middleware.BrowserReloadMiddleware",
    ]

ROOT_URLCONF = "internetnl.urls"
ROOT_HOSTCONF = "internetnl.hosts"
DEFAULT_HOST = "www"

WSGI_APPLICATION = "internetnl.wsgi.application"

# --- Database configuration
#     https://docs.djangoproject.com/en/1.11/ref/settings/#databases

# issue 599 https://github.com/internetstandards/Internet.nl/issues/599
DEFAULT_AUTO_FIELD = "django.db.models.AutoField"

"""
PSQL settings for development purposes (no db restrictions for this user):
This creates the standard development database ('internetnl') and one for test: test_internetnl

create database internetnl;
create role internetnluser with password 'internetnluser';
ALTER role internetnluser with password 'internetnluser';
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
        "NAME": f"{DB_NAME}.sqlite3",
    },
    "default": {
        "ENGINE": "django.db.backends.postgresql_psycopg2",
        "NAME": DB_NAME,
        "USER": DB_USER,
        "PASSWORD": DB_PASSWORD,
        "HOST": DB_HOST,
        "PORT": DB_PORT,
    },
}

# For development, use dev in your own settings.py:
DATABASE = DJANGO_DATABASE
DATABASES = {"default": DATABASES_SETTINGS[DATABASE]}

# --- Cache configuration
#
# This is the setting for django-redis https://pypi.org/project/django-redis/
#
if CACHE_ENABLED:
    CACHES = {
        "default": {
            "BACKEND": "django_redis.cache.RedisCache",
            "LOCATION": CACHE_LOCATION,
            "OPTIONS": {
                "CLIENT_CLASS": "django_redis.client.DefaultClient",
            },
        }
    }

CACHE_TTL = int(os.getenv("INTERNETNL_CACHE_TTL", 200))
CACHE_WHOIS_TTL = 60 * 60 * 24
# Specify domain names for which the cache may be reset through /clear/<dname>
CACHE_RESET_ALLOWLIST = os.getenv("INTERNETNL_CACHE_RESET_ALLOWLIST", "").split(",")

# --- Language settings
#
# Internationalization and Locatization fixed to dutch at this time.
# A single installation will only server one target audience.
USE_I18N = True
USE_L10N = False
USE_TZ = True

# Supported languages.
# Read languages passed in from .env files. See documentation/Customize.md
LANGUAGES = [(landcode, "") for landcode in os.getenv("LANGUAGES", "nl,en").split(",")]

# set the default language to first language in the list
LANGUAGE_CODE = LANGUAGES[0][0]

# --- Static files (CSS, JavaScript, Images)
#     https://docs.djangoproject.com/en/1.11/howto/static-files/

STATIC_URL = "/static/"
STATIC_ROOT = os.getenv("STATIC_ROOT", os.path.join(BASE_DIR, "static"))
STATICFILES_DIRS = [
    # include static assets stored outside of the source directories
    os.path.join(BASE_DIR, "assets"),
    # include files generated by `frontend.py` script
    os.path.join(BASE_DIR, "static_frontend"),
]

# --- Celery configuration
#
CELERY_RESULT_EXPIRES = 7200
CELERY_BROKER_HEARTBEAT = 0  # Workaround for https://github.com/celery/celery/issues/4817
CELERY_TASK_ACKS_LATE = True
CELERY_WORKER_PREFETCH_MULTIPLIER = 1

# fix redis connection leaks
CELERY_RESULT_BACKEND_THREAD_SAFE = True

# used for celery-exporter
CELERY_WORKER_SEND_TASK_EVENTS = True
CELERY_TASK_SEND_SENT_EVENT = True

CELERY_IMPORTS = (
    "checks.tasks.update",
    "interface.batch.scheduler",
    "interface.batch.util",
)

# Celery 4 settings
CELERY_TASK_SERIALIZER = "pickle"
CELERY_RESULT_SERIALIZER = "pickle"
# json content type is required for celery events for celery-exporter
CELERY_ACCEPT_CONTENT = ["pickle", "json"]

# Note that all the following queues need to be defined in the celery
# service configuration.
CELERY_TASK_ROUTES = {
    "checks.tasks.dnssec.mail_callback": {"queue": "db_worker"},
    "checks.tasks.dnssec.web_callback": {"queue": "db_worker"},
    "checks.tasks.ipv6.mail_callback": {"queue": "db_worker"},
    "checks.tasks.ipv6.web_callback": {"queue": "db_worker"},
    "checks.tasks.mail.mail_callback": {"queue": "db_worker"},
    "checks.tasks.tls.mail_callback": {"queue": "db_worker"},
    "checks.tasks.tls.web_callback": {"queue": "db_worker"},
    "checks.tasks.appsecpriv.web_callback": {"queue": "db_worker"},
    "checks.tasks.rpki.web_callback": {"queue": "db_worker"},
    "checks.tasks.rpki.mail_callback": {"queue": "db_worker"},
    "interface.views.shared.run_stats_queries": {"queue": "slow_db_worker"},
    "interface.views.shared.update_running_status": {"queue": "slow_db_worker"},
    "checks.tasks.update.update_hof": {"queue": "slow_db_worker"},
    "checks.tasks.tls.web_cert": {"queue": "nassl_worker"},
    "checks.tasks.tls.web_conn": {"queue": "nassl_worker"},
    "checks.tasks.tls.mail_smtp_starttls": {"queue": "nassl_worker"},
    # Spread out all the work of all workers, the resolv worker has most issues with
    #  https://github.com/celery/celery/issues/6819 - so that should be rebooted a bit more often.
    "checks.tasks.ipv6.ns": {"queue": "ipv6_worker"},
    "checks.tasks.ipv6.mx": {"queue": "ipv6_worker"},
    "checks.tasks.ipv6.web": {"queue": "ipv6_worker"},
    "checks.tasks.mail.dmarc": {"queue": "mail_worker"},
    "checks.tasks.mail.dkim": {"queue": "mail_worker"},
    "checks.tasks.mail.spf": {"queue": "mail_worker"},
    "checks.tasks.tls.web_http": {"queue": "web_worker"},
    "checks.tasks.appsecpriv.web_appsecpriv": {"queue": "web_worker"},
    "checks.tasks.rpki.mail_ns_rpki": {"queue": "rpki_worker"},
    "checks.tasks.rpki.mail_mx_ns_rpki": {"queue": "rpki_worker"},
    "checks.tasks.rpki.mail_rpki": {"queue": "rpki_worker"},
    "checks.tasks.rpki.ns_rpki": {"queue": "rpki_worker"},
    "checks.tasks.rpki.web_rpki": {"queue": "rpki_worker"},
    "checks.tasks.shared.mail_get_servers": {"queue": "resolv_worker"},
    "checks.tasks.shared.resolve_a_aaaa": {"queue": "resolv_worker"},
    "checks.tasks.dnssec.mail_is_secure": {"queue": "dnssec_worker"},
    "checks.tasks.dnssec.web_is_secure": {"queue": "dnssec_worker"},
}

# --- Batch configuration
CELERY_BATCH_TASK_ROUTES = {
    "checks.tasks.dnssec.batch_mail_callback": {"queue": "batch_callback"},
    "checks.tasks.dnssec.batch_mail_is_secure": {"queue": "batch_main"},
    "checks.tasks.dnssec.batch_web_callback": {"queue": "batch_callback"},
    "checks.tasks.dnssec.batch_web_is_secure": {"queue": "batch_main"},
    "checks.tasks.ipv6.batch_mail_callback": {"queue": "batch_callback"},
    "checks.tasks.ipv6.batch_mx": {"queue": "batch_main"},
    "checks.tasks.ipv6.batch_ns": {"queue": "batch_main"},
    "checks.tasks.ipv6.batch_web": {"queue": "batch_nassl"},
    "checks.tasks.ipv6.batch_web_callback": {"queue": "batch_callback"},
    "checks.tasks.mail.batch_dkim": {"queue": "batch_main"},
    "checks.tasks.mail.batch_dmarc": {"queue": "batch_main"},
    "checks.tasks.mail.batch_mail_callback": {"queue": "batch_callback"},
    "checks.tasks.mail.batch_spf": {"queue": "batch_main"},
    "checks.tasks.shared.batch_mail_get_servers": {"queue": "batch_main"},
    "checks.tasks.shared.batch_resolve_a_aaaa": {"queue": "batch_main"},
    "checks.tasks.tls.batch_mail_callback": {"queue": "batch_callback"},
    "checks.tasks.tls.batch_mail_smtp_starttls": {"queue": "batch_main"},
    "checks.tasks.tls.batch_web_callback": {"queue": "batch_callback"},
    "checks.tasks.tls.batch_web_cert": {"queue": "batch_nassl"},
    "checks.tasks.tls.batch_web_conn": {"queue": "batch_nassl"},
    "checks.tasks.tls.batch_web_http": {"queue": "batch_nassl"},
    "checks.tasks.appsecpriv.batch_web_appsecpriv": {"queue": "batch_main"},
    "checks.tasks.appsecpriv.batch_web_callback": {"queue": "batch_callback"},
    "checks.tasks.rpki.batch_mail_callback": {"queue": "batch_callback"},
    "checks.tasks.rpki.batch_mail_ns_rpki": {"queue": "rpki_worker"},
    "checks.tasks.rpki.batch_mail_mx_ns_rpki": {"queue": "rpki_worker"},
    "checks.tasks.rpki.batch_mail_rpki": {"queue": "rpki_worker"},
    "checks.tasks.rpki.batch_ns_rpki": {"queue": "rpki_worker"},
    "checks.tasks.rpki.batch_web_callback": {"queue": "batch_callback"},
    "checks.tasks.rpki.batch_web_rpki": {"queue": "rpki_worker"},
    "interface.batch.util.batch_async_generate_results": {"queue": "batch_slow"},
    "interface.batch.util.batch_async_register": {"queue": "batch_slow"},
    "interface.batch.scheduler.run": {"queue": "batch_scheduler"},
}
CELERY_TASK_ROUTES.update(CELERY_BATCH_TASK_ROUTES)

# Batch uses rabbitmq
RABBIT_VHOST = "/"
RABBIT_MON_QUEUES = ["batch_main", "batch_nassl"]
# Keep the queue length relatively small.
RABBIT_MON_THRESHOLD = 80

# Test user to run without HTTP-AUTH.
BATCH_TEST_USER = "test_user"

# extract user names from BATCH_AUTH as passwords are handled by the webserver
BATCH_USERS = [x.split(":")[0] for x in os.environ.get("BATCH_AUTH", "").split(",")]
BATCH_USER_DEFAULT_ORGANISATION = os.environ.get("BATCH_USER_DEFAULT_ORGANISATION", "n/a")
BATCH_USER_DEFAULT_EMAIL_DOMAIN = os.environ.get("BATCH_USER_DEFAULT_EMAIL_DOMAIN", "example.com")

BATCH_SCHEDULER_INTERVAL = int(os.environ.get("BATCH_SCHEDULER_INTERVAL", 20))  # seconds
# Number of *domains* to start per scheduler run.
BATCH_SCHEDULER_DOMAINS = 25
# Time in seconds from when a task is sumbitted *to a queue*.
BATCH_MAX_RUNNING_TIME = 60 * 10  # seconds

# Custom results for the /results endpoint.
# Set to `True` to activate, `False` to deactivate.
BATCH_API_CUSTOM_RESULTS = {
    "MailNonSendingDomain": True,
    "MailServersTestableStatus": True,
    "Tls13Support": True,
}
# --- END Batch configuration

# Shared task timings
# These limits have been raised a bit in 2022, as servers with a ton of name servers etc just need more time.
SHARED_TASK_SOFT_TIME_LIMIT_HIGH = 130  # was 90
SHARED_TASK_TIME_LIMIT_HIGH = 150  # was 100
BATCH_SHARED_TASK_SOFT_TIME_LIMIT_HIGH = 60 * 7
BATCH_SHARED_TASK_TIME_LIMIT_HIGH = 60 * 8

# If there is not enough time tests will time out and will not show results. So if it's really really busy
# tasks might have to wait on other tasks. In that case there will be all kinds of weird timeout issues like
# missing the complete TLS tests etc. The time itself does really need to be raised.
SHARED_TASK_SOFT_TIME_LIMIT_MEDIUM = 40  # was 20
SHARED_TASK_TIME_LIMIT_MEDIUM = 60  # was 30

SHARED_TASK_SOFT_TIME_LIMIT_LOW = 20  # was 10
SHARED_TASK_TIME_LIMIT_LOW = 30  # was 15

# --- TLS configuration
#
CA_CERTIFICATES = os.path.join(BASE_DIR, "remote_data/certs/ca-bundle.crt")
CA_FINGERPRINTS = os.path.join(BASE_DIR, "remote_data/certs/root_fingerprints")

# --- Markdown/HTML settings
#
MARKDOWN_DEUX_STYLES = {
    "default": {
        "extras": {
            "code-friendly": None,
            "pyshell": None,
            "footnotes": None,
            "smarty-pants": True,
            "header-ids": True,
            "tables": True,
        },
        "safe_mode": False,  # Bug with relative URLS.
    },
}

BLEACH_ALLOWED_TAGS = [
    "b",
    "i",
    "u",
    "em",
    "strong",
    "a",
    "br",
    "table",
    "thead",
    "th",
    "tbody",
    "tr",
    "td",
]
BLEACH_ALLOWED_ATTRIBUTES = ["href", "title", "alt"]
BLEACH_ALLOWED_STYLES = []
BLEACH_STRIP_TAGS = True
BLEACH_STRIP_COMMENTS = True

# --- Settings for Probe polling
#
JAVASCRIPT_TIMEOUT = 3  # seconds

# --- Miscellaneous settings
#
PADDED_MACS = os.path.join(BASE_DIR, "remote_data/macs/padded_macs.json")
DNS_ROOT_KEY = os.path.join(BASE_DIR, "remote_data/dns/root.key")
# Time to cache consecutive requests to taxing pages.
PAGE_CACHE_TIME = int(os.environ.get("PAGE_CACHE_TIME_SECONDS", 60 * 5))  # seconds
SIMHASH_MAX = 10
PUBLIC_SUFFIX_LIST_URL = (
    os.environ.get("PUBLIC_SUFFIX_LIST_URL") or "https://publicsuffix.org/list/public_suffix_list.dat"
)
PUBLIC_SUFFIX_LIST_RENEWAL = 86400  # 24h

# --- Extra manual HoF page(s)
#
# This is intended to read domains from a file and present them in a separate
# page as part of the Hall of Fame menu.
# The configuration is:
#   MANUAL_HOF = {
#       '<url_part>': {
#           'translate_key': '',
#           'entries_file': '/path/to/yaml/file',
#           'template_file': 'filename.html',
#           'icon_file': 'filename.svg'
#       },
#   }
# * <url_part>, is the url part for the page i.e., /halloffame/<url_part>
# * translate_key, is the translate key to be used when translating text.
#   By default it is the same as <url_part>.
#   The final translate ids would then be:
#   - manual halloffame <translate_key> *
#   These ids need to be available in the translations/*/manual_hof.po files.
# * template_file, is an alternate template HTML file to be used if desired.
#   MUST live inside the checks/templates folder.
#   Leave empty if you want to use the default template file (the same as with
#   standard HoF).
# * entries_file, is the filepath to a *yaml* file
#   containing a list of domains with the following format:
#   - domain: "internet.nl"
#     permalink: "https://internet.nl"
#   - domain: "example.nl"
#     permalink: "https://example.nl"
# * icon_file, is the filepath to an icon to be used for this HoF; MUST live
#   inside the checks/static/icons folder.
#
# You can add more <url_part> in the MANUAL_HOF dictionary for additional
# manual HoFs.
#
# Leaving the MANUAL_HOF dictionary empty disables the manual HoF functionality.
#
# As an example, what triggered the manual HoF was the incentive from
# internet.nl to be approached by hosters in order (after manual testing and
# agreement) to be included in a hosters HoF.
MANUAL_HOF = {}

if "hosters" in MANUAL_HOF_PAGES:
    MANUAL_HOF["hosters"] = {
        "translate_key": "",
        "entries_file": os.path.join(BASE_DIR, "manual-hall-of-fame/hosters.yaml"),
        "template_file": "halloffame-hosters.html",
        "icon_file": "embed-badge-hosters-v3.svg",
    }

HOF_UPDATE_INTERVAL = 600  # seconds

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",  # sys.stdout
            "formatter": "color",
        },
        "file": {
            "level": "DEBUG" if DEBUG_LOG else "INFO",
            "class": "logging.FileHandler",
            "filename": "django.log",
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
            "handlers": ["console", "file"],
            "level": DJANGO_LOG_LEVEL,
        },
        "internetnl": {
            "handlers": ["console", "file"],
            "level": INTERNETNL_LOG_LEVEL,
        },
        # ERROR disables verbose task logging (ie: "received task...", "...succeeded in...")
        "celery.app.trace": {
            "handlers": ["console"],
            "level": CELERY_LOG_LEVEL,
        },
        "celery.worker.strategy": {
            "level": CELERY_LOG_LEVEL,
        },
    },
}

MEDIA_ROOT = BASE_DIR

if SECRET_KEY == "secret" and not SKIP_SECRET_KEY_CHECK:
    print("FATAL: the secret key in the config has not yet been configured. Quitting.")
    exit(-1)
    # Todo: exit the app. Currently not known how things run exactly in production.

if DJANGO_IS_PROXIED:
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# Limit the number of tests a client can perform in single test.
# This is the maximum number of tasks that can be run simultaneously per client IP.
# The counter is increased when a task starts, decreased when a task completes,
# and the Redis entry has a 2-hour expiry. Task is an individual category, e.g. RPKI web,
# which means one domain test is 5 tasks.
CLIENT_RATE_LIMIT = int(getenv("CLIENT_RATE_LIMIT", 30))

# --- Routinator settings
#
ROUTINATOR_URL = getenv("ROUTINATOR_URL", "http://localhost:9556/api/v1/validity")

VERSION = get_version(version_scheme="release-branch-semver")

# Sentry reads SENTRY_DSN directly from environment
# DSN is on https://sentry.io/settings/dutch-internet-standards-platform/projects/internetnl/keys/
if getenv("SENTRY_DSN"):
    sentry_sdk.init(
        environment=getenv("SENTRY_ENVIRONMENT", "unknown"),
        traces_sample_rate=0,
        send_default_pii=False,
        before_send=remove_sentry_pii,
        before_breadcrumb=remove_sentry_pii,
        # add version number to sentry events
        release=VERSION,
        # overwrite server_name to not use the container server name
        server_name=getenv("SENTRY_SERVER_NAME"),
    )
    sentry_sdk.set_tag("container_name", str(socket.gethostname()))

# Settings for statsd metrics collection. Statsd defaults over UDP port 8125.
# https://django-statsd.readthedocs.io/en/latest/#celery-signals-integration
STATSD_HOST = os.environ.get("STATSD_HOST", "127.0.0.1")
STATSD_PORT = os.environ.get("STATSD_PORT", "8125")
# add tag support via statshog
STATSD_TELEGRAF = True
STATSD_CLIENT = "statshog"
STATSD_PREFIX = os.environ.get("STATSD_PREFIX", "internetnl")
# celery-exporter gives better metrics
STATSD_CELERY_SIGNALS = False
# send database query metric (in production, in development we have debug toolbar for this)
if not DEBUG:
    STATSD_PATCHES = [
        "django_statsd.patches.db",
    ]


INTEGRATION_TESTS = get_boolean_env("INTEGRATION_TESTS", False)
IPV4_IP_RESOLVER_INTERNAL_VALIDATING = getenv("IPV4_IP_RESOLVER_INTERNAL_VALIDATING")

INTERNETNL_BRANDING = get_boolean_env("INTERNETNL_BRANDING", False)

# 'common crawler format'
# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/User-Agent#crawler_and_bot_ua_strings)
USER_AGENT_URL = getenv(
    "USER_AGENT_URL",
    "https://internet.nl/about/" if INTERNETNL_BRANDING else f"https://{getenv('INTERNETNL_DOMAINNAME')}/",
)

USER_AGENT = f"Mozilla/5.0 (compatible; internetnl/{VERSION}; +{USER_AGENT_URL})"
