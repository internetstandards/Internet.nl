import pytest

from checks.hsts.parser import parse_hsts_header, HSTSParseError, HSTSRecommendation


def test_parse_hsts_header():
    valid_headers = [
        ("max-age=31536000", {"max-age": 31536000}, []),
        ('max-age="31536000"', {"max-age": 31536000}, []),
        ("MAX-AGE=31536000; INCLUDESUBDOMAINS", {"max-age": 31536000, "includesubdomains": True}, []),
        (
            "max-age=31536000; includeSubDomains; preload",
            {"max-age": 31536000, "includesubdomains": True, "preload": True},
            [],
        ),
        ("  max-age=0 ;  includeSubDomains ;  ", {"max-age": 0, "includesubdomains": True}, []),
        (
            "max-age=31536000; preload=1",
            {"max-age": 31536000, "preload": "1"},
            [HSTSRecommendation("invalid-preload-value", {"directive_value": "1"})],
        ),
        (
            "max-age=31536000; custom=foo",
            {"max-age": 31536000, "custom": "foo"},
            [
                HSTSRecommendation(
                    "unknown-directive",
                    {"directive_name": "custom", "directive_value": "foo"},
                )
            ],
        ),
    ]

    for header, expected_directives, expected_recommendations in valid_headers:
        directives, recommendations = parse_hsts_header(header)
        assert directives == expected_directives
        assert recommendations == expected_recommendations

    invalid_headers = [
        "",  # Missing required max-age
        "includeSubDomains",  # Missing required max-age
        "max-age",  # max-age without value
        "max-age=",  # Empty max-age value
        "max-age=-1",  # Negative max-age
        "max-age=²",  # Non-ASCII Unicode superscript digit
        "max-age=31536000; includeSubDomains=1",  # Known valueless directive with value
        "max-age=31536000; max-age=31536000",  # Duplicate directive
        "max-age=31536000; includeSubDomains; INCLUDESUBDOMAINS",  # Duplicate directive (case-insensitive)
        "max-age=31536000; 💩",  # Invalid token character
    ]

    for header in invalid_headers:
        with pytest.raises(HSTSParseError):
            parse_hsts_header(header)
