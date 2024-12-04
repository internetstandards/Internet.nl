import enum
from os import getenv
from typing import List, cast, Tuple, Optional, Any

import dns
from dns.edns import EDECode
from dns.exception import ValidationFailure
from dns.flags import Flag, EDNSFlag
from dns.message import Message
from dns.rdatatype import RdataType
from dns.resolver import Resolver

# TODO: see how timeouts are handled
# TODO: finetune naming of calls
# TODO: don't return dnssecstatus on most queries


class DNSSECStatus(enum.IntEnum):
    SECURE = 1
    BOGUS = 2
    UNSIGNED = 3

    @classmethod
    def from_message(cls, message: Message):
        # TODO: there is also SIGNATURE_EXPIRED etc.
        if any([error.code == EDECode.DNSSEC_BOGUS for error in extended_errors_from_answer(message)]):
            return cls(DNSSECStatus.BOGUS)
        if message.flags & Flag.AD:
            return cls(DNSSECStatus.SECURE)
        return cls(DNSSECStatus.UNSIGNED)


def resolve_a(label: str, allow_bogus=True) -> Tuple[List[str], DNSSECStatus]:
    rrset, dnssec_status = resolve(label, RdataType.A, allow_bogus)
    return [rr.address for rr in rrset], dnssec_status


def resolve_aaaa(label: str, allow_bogus=True) -> Tuple[List[str], DNSSECStatus]:
    rrset, dnssec_status = resolve(label, RdataType.AAAA, allow_bogus)
    return [rr.address for rr in rrset], dnssec_status


def dns_resolve_mx(label: str, allow_bogus=True) -> Tuple[List[Tuple[str, int]], DNSSECStatus]:
    rrset, dnssec_status = resolve(label, RdataType.MX, allow_bogus)
    return [(str(rr.exchange), rr.preference) for rr in rrset], dnssec_status


def resolve_soa(label: str, allow_bogus=True) -> DNSSECStatus:
    rrset, dnssec_status = resolve(label, RdataType.SOA, allow_bogus)
    return dnssec_status


def dns_resolve_ns(label: str, allow_bogus=True) -> Tuple[List[str], DNSSECStatus]:
    rrset, dnssec_status = resolve(label, RdataType.NS, allow_bogus)
    return [str(rr.target) for rr in rrset], dnssec_status


# TODO: try to use TLSA return type
def resolve_tlsa(label: str, allow_bogus=True) -> Tuple[List[Any], DNSSECStatus]:
    rrset, dnssec_status = resolve(label, RdataType.TLSA, allow_bogus)
    return rrset, dnssec_status


def resolve_txt(label: str, allow_bogus=True) -> Tuple[List[str], DNSSECStatus]:
    rrset, dnssec_status = resolve(label, RdataType.TXT, allow_bogus)
    return [rr.to_text()[1:-1] for rr in rrset], dnssec_status


def resolve_spf(label: str, allow_bogus=True) -> Tuple[Optional[str], DNSSECStatus]:
    strings, dnssec_status = resolve_txt(label, allow_bogus)
    spf_records = [s for s in strings if s.lower().startswith("v=spf1")]
    result = spf_records[0] if len(spf_records) == 1 else None
    return result, dnssec_status


def resolve_reverse(label: str) -> List[str]:
    answer = get_resolver().resolve_address(label)
    return [rr.to_text() for rr in answer.rrset]


def resolve(label: str, rr_type: RdataType, allow_bogus=True):
    answer = get_resolver().resolve(dns.name.from_text(label), rr_type)
    dnssec_status = DNSSECStatus.from_message(answer.response)
    if dnssec_status == DNSSECStatus.BOGUS and not allow_bogus:
        raise ValidationFailure()
    return answer.rrset, dnssec_status


_resolver = None


def get_resolver():
    # Resolvers are thread safe once configured
    global _resolver
    if not _resolver:
        _resolver = _create_resolver()
    return _resolver


def _create_resolver() -> Resolver:
    resolver = Resolver(configure=False)
    resolver.nameservers = [getenv("IPV4_IP_RESOLVER_INTERNAL_VALIDATING")]
    # TODO: revert to
    #  # resolver.nameservers = [settings.IPV4_IP_RESOLVER_INTERNAL_VALIDATING]
    resolver.edns = True
    resolver.flags = Flag.CD
    resolver.ednsflags = EDNSFlag.DO
    return resolver


# dnspython 2.7 has this built in on Message
def extended_errors_from_answer(message: Message) -> List[dns.edns.EDEOption]:
    ede_options = [option for option in message.options if option.otype == dns.edns.OptionType.EDE]
    return cast(List[dns.edns.EDEOption], ede_options)
