# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
from checks import scoring
from checks.securitytxt import (
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
        content_type="text/plain; charset=csutf8",
        domain="example.com",
        path=SECURITYTXT_EXPECTED_PATH,
        content=sectxt_content,
        found_host="example.nl",
    ):
        return _evaluate_response(status, content_type, domain, path, content, found_host)

    result = _evaluate_with_valid_defaults()
    assert result == SecuritytxtRetrieveResult(
        found=True,
        content=sectxt_content,
        url="https://example.com/.well-known/security.txt",
        found_host="example.nl",
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
        errors=["Error: security.txt could not be located."],
    )

    result = _evaluate_with_valid_defaults(
        status=500,
    )
    assert result == SecuritytxtRetrieveResult(
        found=False,
        content=sectxt_content,
        url="https://example.com/.well-known/security.txt",
        found_host="example.nl",
        errors=["Error: security.txt could not be located (unexpected HTTP response code 500)."],
    )

    result = _evaluate_with_valid_defaults(
        content_type="; header invalid 💩",
    )
    assert result == SecuritytxtRetrieveResult(
        found=True,
        content=None,
        url="https://example.com/.well-known/security.txt",
        found_host="example.nl",
        errors=["Error: Media type in Content-Type header must be 'text/plain'."],
    )

    result = _evaluate_with_valid_defaults(
        content_type="text/html",
    )
    assert result == SecuritytxtRetrieveResult(
        found=True,
        content=None,
        url="https://example.com/.well-known/security.txt",
        found_host="example.nl",
        errors=["Error: Media type in Content-Type header must be 'text/plain'."],
    )

    result = _evaluate_with_valid_defaults(
        content_type="text/plain; charset=iso8859-1",
    )
    assert result == SecuritytxtRetrieveResult(
        found=True,
        content=sectxt_content,
        url="https://example.com/.well-known/security.txt",
        found_host="example.nl",
        errors=["Error: Charset parameter in Content-Type header must be 'utf-8' if present."],
    )

    result = _evaluate_with_valid_defaults(
        path=SECURITYTXT_LEGACY_PATH,
    )
    assert result == SecuritytxtRetrieveResult(
        found=True,
        content=sectxt_content,
        url="https://example.com/security.txt",
        found_host="example.nl",
        errors=[
            "Error: security.txt was located on the top-level path (legacy place), "
            "but must be placed under the '/.well-known/' path."
        ],
    )


def test_evaluate_securitytxt():
    result = SecuritytxtRetrieveResult(
        found=False,
        content="",
        url="https://example.com/security.txt",
        found_host="host",
        errors=["Error: network error"],
    )
    assert _evaluate_securitytxt(result) == {
        "securitytxt_enabled": False,
        "securitytxt_score": scoring.WEB_APPSECPRIV_SECURITYTXT_BAD,
        "securitytxt_found_host": "host",
        "securitytxt_errors": ["Error: network error"],
        "securitytxt_recommendations": [],
    }

    result = SecuritytxtRetrieveResult(
        found=True,
        content="invalid content",
        url="https://example.com/security.txt",
        found_host="host",
        errors=[],
    )
    assert _evaluate_securitytxt(result) == {
        "securitytxt_enabled": True,
        "securitytxt_score": scoring.WEB_APPSECPRIV_SECURITYTXT_BAD,
        "securitytxt_found_host": "host",
        "securitytxt_errors": [
            "Error: Line must contain a field name and value, unless the line is blank or contains a comment. (line 1)",
            "Error: 'Expires' field must be present.",
            "Error: 'Contact' field must appear at least once.",
        ],
        "securitytxt_recommendations": ["Recommendation: security.txt should be digitally signed."],
    }

    result = SecuritytxtRetrieveResult(
        found=True,
        content="Expires: 2050-09-01T00:00:00.000Z\nContact: mailto:security@example.com",
        url="https://example.com/security.txt",
        found_host="host",
        errors=["Error: content-type error"],
    )
    assert _evaluate_securitytxt(result) == {
        "securitytxt_enabled": True,
        "securitytxt_score": scoring.WEB_APPSECPRIV_SECURITYTXT_BAD,
        "securitytxt_found_host": "host",
        "securitytxt_errors": ["Error: content-type error"],
        "securitytxt_recommendations": [
            "Recommendation: Date and time in 'Expires' field should be less than a year into the future. (line 1)",
            "Recommendation: 'Encryption' field should be present when 'Contact' field contains an email address.",
            "Recommendation: security.txt should be digitally signed.",
        ],
    }

    result = SecuritytxtRetrieveResult(
        found=True,
        content="Expires: 2050-09-01T00:00:00.000Z\nContact: mailto:security@example.com",
        url="https://example.com/security.txt",
        found_host="host",
        errors=[],
    )
    assert _evaluate_securitytxt(result) == {
        "securitytxt_enabled": True,
        "securitytxt_score": scoring.WEB_APPSECPRIV_SECURITYTXT_GOOD,
        "securitytxt_found_host": "host",
        "securitytxt_errors": [],
        "securitytxt_recommendations": [
            "Recommendation: Date and time in 'Expires' field should be less than a year into the future. (line 1)",
            "Recommendation: 'Encryption' field should be present when 'Contact' field contains an email address.",
            "Recommendation: security.txt should be digitally signed.",
        ],
    }
