# Copyright: 2022-2024, ECP, NLnet Labs, the Internet.nl contributors and SYS4 AG.
# SPDX-License-Identifier: Apache-2.0

'''
SMTP TLS Reporting policy parser as defined by:

  RFC 8460, Section "3. Reporting Policy", see: 
  https://datatracker.ietf.org/doc/html/rfc8460#section-3
'''

from pyparsing import (
    Literal,
    CaselessLiteral,
    Combine,
    ParseException,
    Regex,
    White,
    Word,
    ZeroOrMore,
    alphanums,
    pyparsing_common,
    delimitedList,
)


WSP = White(ws=' ', exact=1).suppress()   # Whitespace

field_delim = ZeroOrMore(WSP) + Literal(';') + ZeroOrMore(WSP)   # Fields are semicolon-delimited
ura_delim = ZeroOrMore(WSP) + Literal(',') + ZeroOrMore(WSP)   # multiple RUAs are comma-delimited

tlsrpt_ext_name = Word(alphanums, alphanums+"_-.", max=32)
tlsrpt_ext_value = Word(alphanums, alphanums+"_-.")
tlsrpt_extension = ZeroOrMore(tlsrpt_ext_name + Literal('=') + tlsrpt_ext_value)

# RegEx for parsing email.
regex_tld = r"(?:[a-zA-Z]{2,63}|xn--[a-zA-Z0-9]+)"
regex_mailaddr = (
    r"(?P<mailaddr>([a-zA-Z0-9]{0,61}@)?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+" r"" + regex_tld + ")"
)
mail_uri = Combine(CaselessLiteral("mailto:") + Regex(regex_mailaddr))
tlsrpt_rua = Literal("rua=") +\
        delimitedList(mail_uri | pyparsing_common.url, delim=',').setResultsName('tlsrpt_uri')

tlsrpt_field = tlsrpt_rua + ZeroOrMore(field_delim + tlsrpt_extension)

# Literal will match the version string as required by the ABNF in the RFC:
# tlsrpt-version    = %s"v=TLSRPTv1"
version = Literal("v=TLSRPTv1").setResultsName("tlsrpt_version")

record = version + field_delim + tlsrpt_field


def parse_silent(tlsrpt_record):
    """
    Will return None if there was a parsing error and a ParseResult object otherwise.
    """
    try:
        parsed = record.parseString(tlsrpt_record)
    except ParseException:
        parsed = None
    except Exception as e:
        print(f"{e.__class__.__name__}: {e}")
        parsed = None
    return parsed
