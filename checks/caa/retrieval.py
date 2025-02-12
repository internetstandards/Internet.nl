from dataclasses import dataclass, field
from typing import Optional
from dns.rdtypes.ANY import CAA

from dns.resolver import NoAnswer, NXDOMAIN, LifetimeTimeout, NoNameservers

from checks import scoring
from checks.caa.parser import validate_caa_record, CAAParseError
from checks.resolver import dns_resolve_caa
from checks.tasks.shared import TranslatableTechTableItem


@dataclass
class CAAResult:
    enabled: bool
    canonical_name: Optional[str] = None
    errors: list[TranslatableTechTableItem] = field(default_factory=list)
    recommendations: list[TranslatableTechTableItem] = field(default_factory=list)
    caa_records: list[CAA] = field(default_factory=list)

    @property
    def score(self) -> int:
        return scoring.CAA_GOOD if self.enabled and not self.errors else scoring.CAA_BAD


def retrieve_parse_caa(target_domain: str) -> CAAResult:
    try:
        canonical_name, rrset = dns_resolve_caa(target_domain)
    except (NoAnswer, NXDOMAIN, LifetimeTimeout, NoNameservers):
        return CAAResult(enabled=False)

    result = CAAResult(enabled=True, canonical_name=canonical_name, caa_records=rrset)
    for caa in rrset:
        try:
            validate_caa_record(caa.flags, caa.tag.decode("ascii"), caa.value.decode("ascii"))
        except CAAParseError as cpe:
            result.errors.append(TranslatableTechTableItem(cpe.msg_id, cpe.context))
    return result
