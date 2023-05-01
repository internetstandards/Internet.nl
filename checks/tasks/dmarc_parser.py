# Copyright: 2022, ECP, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
from urllib.parse import urlparse

from pyparsing import (
    CaselessLiteral,
    Combine,
    Group,
    Literal,
    Optional,
    ParseException,
    ParserElement,
    Regex,
    StringEnd,
    White,
    Word,
    ZeroOrMore,
    alphanums,
    nums,
)

ParserElement.setDefaultWhitespaceChars("")  # Whitespace is in the grammar

# Parser for DMARC records.
#
# The record is parsed based on section 6.4 (Formal Definition) of RFC-7489.
# [ https://tools.ietf.org/html/rfc7489#section-6.4 ]
#
# Most of the tokens have been combined together for easier access to the
# records parts.
# The following directives can be found under <parsed_result>['directives']
# if any:
#     - request, (p=);
#     - nrequest, (np=);
#     - srequest, (sp=);
#     - auri, (rua=);
#     - furi, (ruf=);
#     - adkim, (adkim=);
#     - aspf, (aspf=);
#     - ainterval, (ri=);
#     - fo, (fo=);
#     - rfmt, (rf=);
#     - percent, (pct=).

WSP = Optional(White(ws=" ")).suppress()

sep = (WSP + CaselessLiteral(";") + WSP).suppress()
equal = WSP + Literal("=") + WSP


def _check_keyword(tokens):
    if tokens[0][-1] == "-":
        raise ParseException("'-' found at the end of keyword.")
    return None


keyword = Word(alphanums + "-").setParseAction(_check_keyword)

dmarc_uri_numeric = Word(nums) + Optional(
    CaselessLiteral("k") | CaselessLiteral("m") | CaselessLiteral("g") | CaselessLiteral("t")
)


def _check_dmarc_uri(tokens):
    """
    Helper function to parse URIs.

    """
    uri = tokens[0]
    ex_num = uri.count("!")
    if ex_num > 1:
        raise ParseException("Non-encoded '!' found in url.")
    elif ex_num == 1:
        uri, numeric = uri.split("!")
        dmarc_uri_numeric.parseString(numeric)
    try:
        urlparse(uri)
    except ValueError:
        raise ParseException("Could not parse URI.")
    return None


dmarc_uri = Regex("[^ ,;]+").setParseAction(_check_dmarc_uri)
percent = Combine(CaselessLiteral("pct") + equal + Word(nums, max=3))("percent")
rfmt = Combine(CaselessLiteral("rf") + equal + keyword + ZeroOrMore(WSP + Literal(":") + keyword))("rfmt")
fo = Combine(
    CaselessLiteral("fo")
    + equal
    + (CaselessLiteral("0") | CaselessLiteral("1") | CaselessLiteral("d") | CaselessLiteral("s"))
    + ZeroOrMore(
        WSP
        + Literal(":")
        + WSP
        + (CaselessLiteral("0") | CaselessLiteral("1") | CaselessLiteral("d") | CaselessLiteral("s"))
    )
)("fo")
ainterval = Combine(CaselessLiteral("ri") + equal + Word(nums))("ainterval")
aspf = Combine(CaselessLiteral("aspf") + equal + (CaselessLiteral("r") | CaselessLiteral("s")))("aspf")
adkim = Combine(CaselessLiteral("adkim") + equal + (CaselessLiteral("r") | CaselessLiteral("s")))("adkim")
furi = Combine(CaselessLiteral("ruf") + equal + dmarc_uri + ZeroOrMore(WSP + Literal(",") + WSP + dmarc_uri))("furi")
auri = Combine(CaselessLiteral("rua") + equal + dmarc_uri + ZeroOrMore(WSP + Literal(",") + WSP + dmarc_uri))("auri")
srequest = Combine(
    CaselessLiteral("sp")
    + equal
    + (CaselessLiteral("none") | CaselessLiteral("quarantine") | CaselessLiteral("reject"))
)("srequest")
nrequest = Combine(
    CaselessLiteral("np")
    + equal
    + (CaselessLiteral("none") | CaselessLiteral("quarantine") | CaselessLiteral("reject"))
)("nrequest")
request = Combine(
    CaselessLiteral("p") + equal + (CaselessLiteral("none") | CaselessLiteral("quarantine") | CaselessLiteral("reject"))
)("request")
version = Combine(CaselessLiteral("v") + equal + Literal("DMARC1"))
directives = (
    Optional(request)
    + (
        Optional(sep + srequest)
        & Optional(sep + nrequest)
        & Optional(sep + auri)
        & Optional(sep + furi)
        & Optional(sep + adkim)
        & Optional(sep + aspf)
        & Optional(sep + ainterval)
        & Optional(sep + fo)
        & Optional(sep + rfmt)
        & Optional(sep + percent)
    )
    + Optional(sep)
)
record = version("version") + sep + Group(directives)("directives") + StringEnd()


def parse(dmarc_record):
    try:
        parsed = record.parseString(dmarc_record)
    except ParseException:
        parsed = None
    except Exception as e:
        print(f"{e.__class__.__name__}: {e}")
        parsed = None
    return parsed
