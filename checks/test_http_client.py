from types import SimpleNamespace

import pytest
import requests
from urllib3.exceptions import LocationParseError

from checks.http_client import http_get


class InvalidRedirectSession:
    def __init__(self):
        self.calls = 0
        self.initial_response = requests.Response()
        self.initial_response.status_code = 302
        self.initial_response.url = "https://example.test/"
        self.initial_response.history = []
        self.initial_response._next = SimpleNamespace(url="https://./")

    def get(self, *args, **kwargs):
        self.calls += 1
        if self.calls % 2:
            return self.initial_response
        raise LocationParseError(".")


def test_http_get_normalizes_malformed_redirect_error():
    session = InvalidRedirectSession()

    with pytest.raises(requests.exceptions.InvalidURL) as exc_info:
        http_get("https://example.test/", session=session)

    assert isinstance(exc_info.value.__cause__, LocationParseError)
    assert session.calls == 4
