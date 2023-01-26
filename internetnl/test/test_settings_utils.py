from internetnl.settings_utils import split_csv_trim, get_boolean_env, remove_sentry_pii


def test_split_csv_trim():
    assert split_csv_trim("") == []
    assert split_csv_trim("A") == ["A"]
    assert split_csv_trim(" a , b , c ") == ["a", "b", "c"]
    assert split_csv_trim(" 1 , 2 , 3 ") == ["1", "2", "3"]


def test_get_boolean_env_nothing_set():
    assert get_boolean_env("NON_EXISTANT", False) is False
    assert get_boolean_env("NON_EXISTANT", True) is True


def test_get_boolean_env_set_true(monkeypatch):
    # https://dev.to/mhihasan/testing-environment-variable-in-pytest-38ec
    monkeypatch.setenv("NON_EXISTANT", "True")

    assert get_boolean_env("NON_EXISTANT", False) is True
    assert get_boolean_env("NON_EXISTANT", True) is True


def test_get_boolean_env_set_false(monkeypatch):
    # https://dev.to/mhihasan/testing-environment-variable-in-pytest-38ec
    monkeypatch.setenv("NON_EXISTANT", "False")

    assert get_boolean_env("NON_EXISTANT", True) is False
    assert get_boolean_env("NON_EXISTANT", False) is False


def test_remove_sentry_pii():

    mock_event_regular = {
        "exception": {
            "values": [
                {
                    "type": "ValueError",
                    "value": "sentry test",
                    "stacktrace": {
                        "frames": [
                            {
                                "vars": {
                                    "category": "<checks.categories.WebRpki object at 0x7f12e74ea310>",
                                    "domain": "'internet.nl'",
                                    "req_limit_id": "'dom:req_limit:2a10:3781:22b2:1:40e3:f0be:3aeb:c0cd'",
                                },
                            },
                        ]
                    },
                }
            ]
        },
        "extra": {
            "celery-job": {
                "args": [
                    [
                        [
                            "'rpki_web'",
                            "defaultdict(<class 'list'>, {'...",
                        ],
                        [
                            "'rpki_ns'",
                            "defaultdict(<class 'list'>, {'ns1.s ...",
                        ],
                    ],
                    "internet.nl",
                    "dom:req_limit:2a10:3781:22b2:1:40e3:f0be:3aeb:c0cd",
                ],
                "kwargs": {},
                "task_name": "checks.tasks.rpki.web_callback",
            },
        },
    }
    mock_event_regular_cleaned = remove_sentry_pii(mock_event_regular, None)
    assert (
        "2a10"
        not in mock_event_regular_cleaned["exception"]["values"][0]["stacktrace"]["frames"][0]["vars"]["req_limit_id"]
    )
    assert "2a10" not in mock_event_regular_cleaned["extra"]["celery-job"]["args"][2]

    mock_event_conntest = {
        "breadcrumbs": {
            "values": [
                {
                    "timestamp": 1675851013.044436,
                    "type": "default",
                    "category": "query",
                    "level": "info",
                    "message": "q",
                },
            ]
        },
        "exception": {
            "values": [
                {
                    "value": "conn sentry test",
                    "stacktrace": {
                        "frames": [
                            {
                                "vars": {
                                    "callback": "<function finished at 0x7f75991ba7a0>",
                                    "callback_args": [],
                                    "callback_kwargs": {"request_id": "'77cf6b0d55fa4188a0c05ceebaf05881'"},
                                    "request": "<WSGIRequest: GET '/connection/finished/...?_=1675851011130'>",
                                    "response": "None",
                                    "self": "<django.core.handlers.wsgi.WSGIHandler object at 0x7f75a1aa4190>",
                                    "wrapped_callback": "<function finished at 0x7f75990df0e0>",
                                },
                            },
                        ]
                    },
                }
            ]
        },
        "request": {
            "url": "http://conn.dev.internet.nl/connection/finished/77cf6b0d55fa4188a0c05ceebaf05881",
        },
    }
    mock_event_conntest_cleaned = remove_sentry_pii(mock_event_conntest, None)
    assert not mock_event_conntest_cleaned["breadcrumbs"]
    assert not mock_event_conntest_cleaned["exception"]["values"][0]["stacktrace"]["frames"][0].get("vars")
