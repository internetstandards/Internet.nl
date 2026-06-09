# Copyright: 2024, ECP, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
import pytest
from pyparsing import ParseException

from checks.tasks.dmarc_parser import _check_dmarc_uri, parse


def test__check_dmarc_uri():
    """
    Check if None is returned on valid URI
    """
    assert _check_dmarc_uri(["mailto:test@example.com"]) is None


def test__check_dmarc_uri_detect_missing_uri_scheme():
    """
    Many people forget to add the mailto: scheme to their DMARC URI.
    This common error should be detected.
    """
    with pytest.raises(ParseException):
        _check_dmarc_uri(["test@example.com"])


def test_parse():
    sample_record = "v=DMARC1; p=none; rua=mailto:dmarc@example.com"
    result = parse(sample_record)
    assert result.version == "v=DMARC1"
    assert result.directives.request == "p=none"
    assert result.directives.auri == "rua=mailto:dmarc@example.com"


def test_parse_rfc9989_tags():
    sample_record = "v=DMARC1; p=reject; sp=reject; np=reject; psd=n; t=y; rua=mailto:dmarc@example.com"
    result = parse(sample_record)
    assert result is not None
    assert result.directives.psd == "psd=n"
    assert result.directives.testing == "t=y"


@pytest.mark.parametrize("value", ["y", "n", "u"])
def test_parse_psd_values(value):
    result = parse(f"v=DMARC1; p=none; psd={value}")
    assert result is not None
    assert result.directives.psd == f"psd={value}"


def test_parse_psd_invalid_value():
    assert parse("v=DMARC1; p=none; psd=x") is None


@pytest.mark.parametrize("value", ["y", "n"])
def test_parse_testing_values(value):
    result = parse(f"v=DMARC1; p=none; t={value}")
    assert result is not None
    assert result.directives.testing == f"t={value}"


def test_parse_testing_invalid_value():
    assert parse("v=DMARC1; p=none; t=x") is None
