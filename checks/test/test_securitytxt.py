# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
from typing import Optional

from checks import scoring
from checks.tasks.securitytxt import (
    SecuritytxtRetrieveResult,
    _evaluate_securitytxt,
    _evaluate_response,
    SECURITYTXT_EXPECTED_PATH,
    SECURITYTXT_LEGACY_PATH,
)


# This test is limited to evaluation, as network retrieval is more appropriately
# tested in an integration test


def test_evaluate_response():
    sectxt_content = "content"

    def _evaluate_with_valid_defaults(
        status=200,
        content_type: Optional[str] = "text/plain; charset=csutf8",
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
        content="",
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
        content="invalid content",
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
            {"msgid": "no_line_separators", "context": {"line_no": None}},
            {"msgid": "no_contact", "context": {"line_no": None}},
        ],
        "securitytxt_recommendations": [{"msgid": "not_signed", "context": {"line_no": None}}],
    }

    result = SecuritytxtRetrieveResult(
        found=True,
        content="Expires: 2050-09-01T00:00:00.000Z\nContact: mailto:security@example.com\n",
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
            "Expires: 2050-09-01T00:00:00.000Z\n"
            "Contact: mailto:security@example.com\n"
            "Canonical: https://host-other/.well-known/security.txt\n"
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
            "Expires: 2050-09-01T00:00:00.000Z\n"
            "Contact: mailto:security@example.com\n"
            "Canonical: https://host/.well-known/security.txt\n"
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
        ],
    }
