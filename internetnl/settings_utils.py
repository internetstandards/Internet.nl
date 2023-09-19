# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
import os
from typing import List
import logging

log = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(__file__))


def split_csv_trim(value: str) -> List[str]:
    # Helper for csv values from the environment.
    # Example: "internet.nl, mysite.org" -> ["internet.nl", "mysite.org"]

    # Prevent a list with a [""] if there is no value in the string. "" is widely seen as empty/not a setting.
    if value == "":
        return []

    return [x.strip() for x in value.split(",")]


def get_boolean_env(key: str, fallback: bool) -> bool:
    # Helper that makes working with boolean settings more straightforward.
    string_value = os.getenv(key, fallback)
    return True if string_value in ["True", True] else False


def check_if_environment_present():
    if os.getenv("ALLOWED_HOSTS"):
        print("Using settings from operating system environment variables (ENV).")
    else:
        print("Using settings from settings.py, ignoring ENV variables.")


def remove_sentry_pii(event, hint):
    """
    Remove known PII from data sent to sentry.
    - Connection test has too much data in local vars and breadcrumbs,
      making it hard to filter correctly, so when "connection" is
      in the URL we remove all of that.
    - Some locals contain user IP for request limiting.
    - Same for some celery args.
    Errs on filtering too much.

    Format of `event` is same as JSON link in Sentry event page.
    """
    conntest = "conn" in event.get("request", {}).get("url", "")
    removed_locals = ["req_limit_id", "remote_addr"]
    removed_celery_match = ["req_limit"]

    if conntest:
        event["breadcrumbs"] = {}

    def clean_exception(target_exception):
        frames = target_exception.get("stacktrace", {}).get("frames", [])
        for frame in frames:
            if conntest:
                frame.pop("vars", None)
            else:
                frame_vars = frame.get("vars", {})
                for arg in removed_locals:
                    if arg in frame_vars:
                        frame_vars[arg] = "[removed]"

    for exception in event.get("exception", {}).get("values", []):
        clean_exception(exception)

    for exception in event.get("threads", {}).get("values", []):
        clean_exception(exception)

    def clean_celery_arg(target_arg):
        needs_removal = any([key in target_arg for key in removed_celery_match])
        return "[removed]" if needs_removal else target_arg

    celery_args = event.get("extra", {}).get("celery-job", {}).get("args", [])
    if celery_args:
        cleaned_args = [clean_celery_arg(arg) for arg in celery_args]
        event["extra"]["celery-job"]["args"] = cleaned_args

    return event
