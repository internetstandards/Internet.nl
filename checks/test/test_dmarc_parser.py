# Copyright: 2024, ECP, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
import pytest
from pyparsing import ParseException, ParseResults

from checks.tasks.dmarc_parser import _check_dmarc_uri, parse


def test__check_dmarc_uri():
    """
    Check if None is returned on valid URI
    """
    assert _check_dmarc_uri(['mailto:test@example.com']) is None


def test__check_dmarc_uri_detect_missing_uri_scheme():
    """
    Many people forget to add the mailto: scheme to their DMARC URI.
    This common error should be detected.
    """
    with pytest.raises(ParseException):
        _check_dmarc_uri(['test@example.com'])


def test_parse():
    sample_record = 'v=DMARC1; p=none; rua=mailto:dmarc@example.com'
    result = parse(sample_record)
    assert result.version == 'v=DMARC1'
    assert result.directives.request == 'p=none'
    assert result.directives.auri == 'rua=mailto:dmarc@example.com'
