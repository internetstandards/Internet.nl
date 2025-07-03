import enum
from typing import Optional, Iterable

import dns
from django.conf import settings
from dns.edns import EDECode
from dns.exception import ValidationFailure
from dns.flags import Flag, EDNSFlag
from dns.message import Message, make_query
from dns.query import udp_with_fallback
from dns.rdatatype import RdataType
from dns.rdtypes.ANY import TLSA, CAA
from dns.resolver import Resolver, NXDOMAIN, NoAnswer

DNS_TIMEOUT = 15


EDE_CODES_BOGUS = [
    EDECode.DNSSEC_BOGUS,
    EDECode.SIGNATURE_EXPIRED,
    EDECode.SIGNATURE_NOT_YET_VALID,
    EDECode.DNSKEY_MISSING,
    EDECode.RRSIGS_MISSING,
    EDECode.NO_ZONE_KEY_BIT_SET,
    EDECode.NSEC_MISSING,
]


class DNSSECStatus(enum.IntEnum):
    SECURE = 1
    BOGUS = 2
    INSECURE = 3

    @classmethod
    def from_message(cls, message: Message):
        if any([error.code in EDE_CODES_BOGUS for error in message.extended_errors()]):
            return cls(DNSSECStatus.BOGUS)
        if message.flags & Flag.AD:
            return cls(DNSSECStatus.SECURE)
        return cls(DNSSECStatus.INSECURE)


def dns_resolve_a(qname: str, allow_bogus=True) -> list[str]:
    rrset, dnssec_status = dns_resolve(qname, RdataType.A, allow_bogus)
    return [rr.address for rr in rrset]


def dns_resolve_aaaa(qname: str, allow_bogus=True) -> list[str]:
    rrset, dnssec_status = dns_resolve(qname, RdataType.AAAA, allow_bogus)
    return [rr.address for rr in rrset]


def dns_resolve_mx(qname: str, allow_bogus=True) -> list[tuple[str, int]]:
    rrset, dnssec_status = dns_resolve(qname, RdataType.MX, allow_bogus)
    return [(str(rr.exchange), rr.preference) for rr in rrset]


def dns_resolve_ns(qname: str, allow_bogus=True) -> list[str]:
    rrset, dnssec_status = dns_resolve(qname, RdataType.NS, allow_bogus)
    return [str(rr.target) for rr in rrset]


def dns_resolve_tlsa(qname: str, allow_bogus=True) -> tuple[list[TLSA], DNSSECStatus]:
    rrset, dnssec_status = dns_resolve(qname, RdataType.TLSA, allow_bogus)
    return rrset, dnssec_status


def dns_resolve_txt(qname: str, allow_bogus=True) -> list[str]:
    rrset, dnssec_status = dns_resolve(qname, RdataType.TXT, allow_bogus)
    return ["".join([dns.rdata._escapify(s) for s in rr.strings]) for rr in rrset]


def dns_resolve_spf(qname: str, allow_bogus=True) -> Optional[str]:
    strings = dns_resolve_txt(qname, allow_bogus)
    spf_records = [s for s in strings if s.lower().startswith("v=spf1")]
    return spf_records[0] if len(spf_records) == 1 else None


def dns_resolve_soa(qname: str, allow_bogus=True, raise_on_no_answer=True) -> DNSSECStatus:
    rrset, dnssec_status = dns_resolve(qname, RdataType.SOA, allow_bogus, raise_on_no_answer)
    return dnssec_status


def dns_resolve_caa(qname: str) -> tuple[str, Iterable[CAA.CAA]]:
    """
    Resolve CAA for a domain, including tree climbing per RFC8659 3.
    Returns the canonical name and the CAA records.
    """
    while True:
        try:
            answer = _get_resolver().resolve(dns.name.from_text(qname), RdataType.CAA, raise_on_no_answer=True)
            return str(answer.canonical_name), answer.rrset
        except (NoAnswer, NXDOMAIN):
            qname = dns_climb_tree(qname)
            if qname is None:
                raise NoAnswer()


def dns_resolve_reverse(ipaddr: str) -> list[str]:
    answer = _get_resolver().resolve_address(ipaddr)
    return [rr.to_text() for rr in answer.rrset]


def dns_check_ns_connectivity(probe_qname: str, target_ip: str, port: int = 53) -> bool:
    q = make_query(probe_qname, RdataType.NS, use_edns=True, flags=Flag.CD)
    try:
        udp_with_fallback(q, port=port, where=target_ip, timeout=DNS_TIMEOUT)
        return True
    except (dns.exception.Timeout, OSError):
        return False


def dns_resolve(qname: str, rr_type: RdataType, allow_bogus=True, raise_on_no_answer=True):
    answer = _get_resolver().resolve(dns.name.from_text(qname), rr_type, raise_on_no_answer=raise_on_no_answer)
    dnssec_status = DNSSECStatus.from_message(answer.response)
    if dnssec_status == DNSSECStatus.BOGUS and not allow_bogus:
        raise ValidationFailure()
    return answer.rrset, dnssec_status


def dns_climb_tree(qname: str) -> Optional[str]:
    parent = dns.name.from_text(qname).parent()
    if parent == dns.name.root:
        return None
    return parent.to_text()


_resolver = None


def _get_resolver():
    # Resolvers are thread safe once configured
    # global _resolver
    # if not _resolver:
    _resolver = _create_resolver()
    return _resolver


def _create_resolver() -> Resolver:
    resolver = Resolver(configure=False)
    resolver.nameservers = [settings.IPV4_IP_RESOLVER_INTERNAL_VALIDATING]
    resolver.edns = True
    resolver.flags = Flag.CD
    resolver.ednsflags = EDNSFlag.DO
    resolver.lifetime = DNS_TIMEOUT
    return resolver
