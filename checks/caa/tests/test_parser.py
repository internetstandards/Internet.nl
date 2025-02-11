import pytest

from checks.caa.parser import validate_caa_record, CAAParseError


def test_validate_caa_record():
    valid_pairs = [
        (0, "issue", ";"),
        (128, "issue", ";"),
        (128, "ISSue", ";"),
        (0, "issue", "ca.example.com"),
        (0, "issuewild", "ca.example.com"),
        (0, "iodef", "https://report.example.com"),
        (0, "iodef", "mailto:report@example.com"),
        (0, "contactemail", "contact@example.com"),
        (0, "contactphone", "+3185123456"),
        (0, "issuevmc", ";"),
        (0, "issuevmc", "ca.example.com"),
        (0, "contactphone", "+3185123456"),
        (0, "issuemail", ";"),
        (0, "issuemail", "authority.example; account=123456"),
        (0, "issue", "example.net; accounturi=https://example.net/account/1234"),
        (0, "issue", "example.net; validationmethods=dns-01,ca-custom"),
        (0, "issuewild", "example.net; accounturi=https://example.net/account/2345; validationmethods=http-01"),
    ]
    for tag, name, value in valid_pairs:
        validate_caa_record(tag, name, value)

    invalid_pairs = [
        (255, "issue", ";"),  # Reserved bit set in flag
        (0, "issue", "%"),  # Invalid issuer domain name
        (0, "issue", "💩"),  # Invalid issuer domain name
        (0, "issuewild", "💩"),  # Invalid issuer domain name
        (0, "issuevmc", "💩"),  # Invalid issuer domain name
        (0, "iodef", "https://"),  # Invalid URL
        (0, "iodef", "ftp://report.example.com"),  # Invalid URL scheme
        (0, "contactemail", "not-an-email"),  # Invalid email address
        (0, "contactphone", "not-a-phone-number"),  # Invalid phone number
        (0, "issuemail", "authority.example; account=💩"),  # Invalid account ID grammar
        (0, "issue", "example.net; validationmethods=dns-01,custom"),  # Invalid validation method
    ]
    for tag, name, value in invalid_pairs:
        with pytest.raises(CAAParseError):
            validate_caa_record(tag, name, value)
