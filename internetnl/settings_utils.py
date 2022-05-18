# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
import os
from typing import List

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
