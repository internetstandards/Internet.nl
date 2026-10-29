# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0

from unittest.mock import Mock, patch

import pytest

from checks import scoring
from checks.tasks.securitytxt import (
    SecuritytxtRetrieveResult,
    _evaluate_securitytxt,
    _evaluate_response,
    _retrieve_securitytxt,
    SECURITYTXT_EXPECTED_PATH,
    SECURITYTXT_LEGACY_PATH,
)

# This test is limited to evaluation, as network retrieval is more appropriately
# tested in an integration test


def test_evaluate_response():
    sectxt_content = b"content"

    def _evaluate_with_valid_defaults(
        status=200,
        content_type: str | None = "text/plain; charset=csutf8",
        domain="example.com",
        path=SECURITYTXT_EXPECTED_PATH,
        content=sectxt_content,
        found_host="example.nl",
        found_url="https://example.nl/.well-known/security.txt",
    ):
        return _evaluate_response(status, content_type, domain, path, content, found_host, found_url)

    result = _evaluate_with_valid_defaults()
    assert result == SecuritytxtRetrieveResult(
        found=True,
        content=sectxt_content,
        url="https://example.com/.well-known/security.txt",
        found_host="example.nl",
        found_url="https://example.nl/.well-known/security.txt",
        errors=[],
    )

    result = _evaluate_with_valid_defaults(
        status=404,
    )
    assert result == SecuritytxtRetrieveResult(
        found=False,
        content=sectxt_content,
        url="https://example.com/.well-known/security.txt",
        found_host="example.nl",
        found_url="https://example.nl/.well-known/security.txt",
        errors=[{"msgid": "no_security_txt_404"}],
    )

    result = _evaluate_with_valid_defaults(
        status=500,
    )
    assert result == SecuritytxtRetrieveResult(
        found=False,
        content=sectxt_content,
        url="https://example.com/.well-known/security.txt",
        found_host="example.nl",
        found_url="https://example.nl/.well-known/security.txt",
        errors=[{"msgid": "no_security_txt_other", "context": {"status_code": 500}}],
    )

    result = _evaluate_with_valid_defaults(
        content_type=None,
    )
    assert result == SecuritytxtRetrieveResult(
        found=True,
        content=None,
        url="https://example.com/.well-known/security.txt",
        found_host="example.nl",
        found_url="https://example.nl/.well-known/security.txt",
        errors=[{"msgid": "no_content_type"}],
    )

    result = _evaluate_with_valid_defaults(
        content_type="; header invalid 💩",
    )
    assert result == SecuritytxtRetrieveResult(
        found=True,
        content=None,
        url="https://example.com/.well-known/security.txt",
        found_host="example.nl",
        found_url="https://example.nl/.well-known/security.txt",
        errors=[{"msgid": "invalid_media"}],
    )

    result = _evaluate_with_valid_defaults(
        content_type="text/html",
    )
    assert result == SecuritytxtRetrieveResult(
        found=True,
        content=None,
        url="https://example.com/.well-known/security.txt",
        found_host="example.nl",
        found_url="https://example.nl/.well-known/security.txt",
        errors=[{"msgid": "invalid_media"}],
    )

    result = _evaluate_with_valid_defaults(
        content_type="text/plain; charset=iso8859-1",
    )
    assert result == SecuritytxtRetrieveResult(
        found=True,
        content=sectxt_content,
        url="https://example.com/.well-known/security.txt",
        found_host="example.nl",
        found_url="https://example.nl/.well-known/security.txt",
        errors=[{"msgid": "invalid_charset"}],
    )

    result = _evaluate_with_valid_defaults(
        path=SECURITYTXT_LEGACY_PATH,
    )
    assert result == SecuritytxtRetrieveResult(
        found=True,
        content=sectxt_content,
        url="https://example.com/security.txt",
        found_host="example.nl",
        found_url="https://example.nl/.well-known/security.txt",
        errors=[{"msgid": "location"}],
    )


def test_evaluate_securitytxt():
    result = SecuritytxtRetrieveResult(
        found=False,
        content=b"",
        url="https://example.com/security.txt",
        found_host="host",
        found_url="https://host/.well-known/security.txt",
        errors=[{"msgid": "example"}],
    )
    assert _evaluate_securitytxt(result) == {
        "securitytxt_enabled": False,
        "securitytxt_score": scoring.WEB_APPSECPRIV_SECURITYTXT_BAD,
        "securitytxt_found_host": "host",
        "securitytxt_errors": [{"msgid": "example"}],
        "securitytxt_recommendations": [],
    }

    result = SecuritytxtRetrieveResult(
        found=True,
        content=b"invalid content",
        url="https://example.com/security.txt",
        found_host="host",
        found_url="https://host/.well-known/security.txt",
        errors=[],
    )
    assert _evaluate_securitytxt(result) == {
        "securitytxt_enabled": True,
        "securitytxt_score": scoring.WEB_APPSECPRIV_SECURITYTXT_BAD,
        "securitytxt_found_host": "host",
        "securitytxt_errors": [
            {"msgid": "invalid_line", "context": {"line_no": 1}},
            {"msgid": "no_expire", "context": {"line_no": None}},
            {"msgid": "no_line_separators", "context": {"line_no": 1}},
            {"msgid": "no_contact", "context": {"line_no": None}},
        ],
        "securitytxt_recommendations": [{"msgid": "not_signed", "context": {"line_no": None}}],
    }

    result = SecuritytxtRetrieveResult(
        found=True,
        content=b"Expires: 2050-09-01T00:00:00.000Z\nContact: mailto:security@example.com\n",
        url="https://example.com/security.txt",
        found_host="host",
        found_url="https://host/.well-known/security.txt",
        errors=[{"msgid": "example"}],
    )
    assert _evaluate_securitytxt(result) == {
        "securitytxt_enabled": True,
        "securitytxt_score": scoring.WEB_APPSECPRIV_SECURITYTXT_BAD,
        "securitytxt_found_host": "host",
        "securitytxt_errors": [{"msgid": "example"}],
        "securitytxt_recommendations": [
            {"msgid": "long_expiry", "context": {"line_no": 1}},
            {"msgid": "no_encryption", "context": {"line_no": None}},
            {"msgid": "not_signed", "context": {"line_no": None}},
        ],
    }

    result = SecuritytxtRetrieveResult(
        found=True,
        content=(
            b"Expires: 2050-09-01T00:00:00.000Z\n"
            b"Contact: mailto:security@example.com\n"
            b"Canonical: https://host-other/.well-known/security.txt\n"
        ),
        url="https://example.com/security.txt",
        found_host="host",
        found_url="https://host/.well-known/security.txt",
        errors=[],
    )
    assert _evaluate_securitytxt(result) == {
        "securitytxt_enabled": True,
        "securitytxt_score": scoring.WEB_APPSECPRIV_SECURITYTXT_GOOD,
        "securitytxt_found_host": "host",
        "securitytxt_errors": [{"msgid": "no_canonical_match", "context": {"line_no": None}}],
        "securitytxt_recommendations": [
            {"msgid": "long_expiry", "context": {"line_no": 1}},
            {"msgid": "no_encryption", "context": {"line_no": None}},
            {"msgid": "not_signed", "context": {"line_no": None}},
        ],
    }

    result = SecuritytxtRetrieveResult(
        found=True,
        content=(
            b"Expires: 2050-09-01T00:00:00.000Z\n"
            b"Contact: mailto:security@example.com\n"
            b"Canonical: https://host/.well-known/security.txt\n"
            b"unknown-field: https://host/.well-known/security.txt\n"
        ),
        url="https://example.com/security.txt",
        found_host="host",
        found_url="https://host/.well-known/security.txt",
        errors=[],
    )
    assert _evaluate_securitytxt(result) == {
        "securitytxt_enabled": True,
        "securitytxt_score": scoring.WEB_APPSECPRIV_SECURITYTXT_GOOD,
        "securitytxt_found_host": "host",
        "securitytxt_errors": [],
        "securitytxt_recommendations": [
            {"msgid": "long_expiry", "context": {"line_no": 1}},
            {"msgid": "no_encryption", "context": {"line_no": None}},
            {"msgid": "not_signed", "context": {"line_no": None}},
            {"msgid": "unknown_field", "context": {"line_no": 4}},
        ],
    }


@pytest.mark.parametrize(
    ("urls", "insecure"),
    [
        (["https://example.com/.well-known/security.txt"], False),
        (
            [
                "https://example.com/.well-known/security.txt",
                "https://cdn.example.com/.well-known/security.txt",
            ],
            False,
        ),
        (
            [
                "https://example.com/.well-known/security.txt",
                "http://cdn.example.com/.well-known/security.txt",
            ],
            True,
        ),
        (
            [
                "https://example.com/.well-known/security.txt",
                "http://redirect.example.com/security.txt",
                "https://cdn.example.com/.well-known/security.txt",
            ],
            True,
        ),
        (
            [
                "https://example.com/.well-known/security.txt",
                "https://first.example.com/redirect",
                "http://second.example.com/redirect",
                "https://cdn.example.com/.well-known/security.txt",
            ],
            True,
        ),
    ],
)
def test_retrieve_securitytxt_redirect_scheme(urls, insecure):
    """A successful response must not hide insecure intermediate redirects."""
    response = Mock(
        status_code=200,
        url=urls[-1],
        headers={"Content-Type": "text/plain; charset=utf-8"},
        history=[Mock(url=url) for url in urls[:-1]],
    )
    content = b"Expires: 2027-06-01T00:00:00Z\nContact: mailto:security@example.com\n"
    with (
        patch("checks.tasks.securitytxt.http_get_ip", return_value=response) as get,
        patch("checks.tasks.securitytxt.response_content_chunk", return_value=content),
    ):
        result = _retrieve_securitytxt(("inet", "127.0.0.1"), "example.com")

    assert get.call_count == 1
    assert result.found
    assert ({"msgid": "invalid_uri_scheme"} in result.errors) is insecure
    evaluation = _evaluate_securitytxt(result)
    assert evaluation["securitytxt_score"] == (
        scoring.WEB_APPSECPRIV_SECURITYTXT_BAD if insecure else scoring.WEB_APPSECPRIV_SECURITYTXT_GOOD
    )


def test_retrieve_securitytxt_ignores_redirects_in_failed_first_location():
    """If the well-known path fails, assess only the final legacy response."""
    first_response = Mock(
        status_code=404,
        url="http://example.com/not-found",
        headers={"Content-Type": "text/plain"},
        history=[Mock(url="https://example.com/.well-known/security.txt")],
    )
    legacy_response = Mock(
        status_code=200,
        url="https://example.com/security.txt",
        headers={"Content-Type": "text/plain"},
        history=[],
    )
    with (
        patch("checks.tasks.securitytxt.http_get_ip", side_effect=[first_response, legacy_response]) as get,
        patch("checks.tasks.securitytxt.response_content_chunk", return_value=b"content"),
    ):
        result = _retrieve_securitytxt(("inet", "127.0.0.1"), "example.com")

    assert get.call_count == 2
    assert result.url == "https://example.com/security.txt"
    assert result.errors == [{"msgid": "location"}]


def test_retrieve_securitytxt_no_scheme_error_when_file_not_found():
    """A missing file is already an error; it must not be reported as found."""
    first_response = Mock(
        status_code=404,
        url="https://example.com/.well-known/security.txt",
        headers={"Content-Type": "text/plain"},
        history=[],
    )
    legacy_response = Mock(
        status_code=404,
        url="http://example.com/security.txt",
        headers={"Content-Type": "text/plain"},
        history=[Mock(url="https://example.com/security.txt")],
    )
    with (
        patch("checks.tasks.securitytxt.http_get_ip", side_effect=[first_response, legacy_response]),
        patch("checks.tasks.securitytxt.response_content_chunk", return_value=b""),
    ):
        result = _retrieve_securitytxt(("inet", "127.0.0.1"), "example.com")

    assert result.found is False
    assert result.errors == [{"msgid": "no_security_txt_404"}]
