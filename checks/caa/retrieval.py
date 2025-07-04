from dataclasses import dataclass, field, InitVar
from typing import Optional, Iterable

import dns
from dns.rdtypes.ANY.CAA import CAA
from dns.resolver import NoAnswer, NXDOMAIN, LifetimeTimeout, NoNameservers

from checks import scoring
from checks.caa.parser import validate_caa_record, CAAParseError
from checks.resolver import dns_resolve_caa
from checks.tasks.shared import TranslatableTechTableItem

CAA_MSGID_INSUFFICIENT_POLICY = "missing-required-property-issue"
CAA_TAGS_REQUIRED = {"issue"}
CAA_MAX_RECORDS = 100


@dataclass
class CAAEvaluation:
    """
    The evaluation of a set of CAA records.
    """

    caa_found: bool
    canonical_name: Optional[str] = None
    errors: list[TranslatableTechTableItem] = field(default_factory=list)
    recommendations: list[TranslatableTechTableItem] = field(default_factory=list)
    caa_records_str: list[str] = field(default_factory=list)
    caa_tags: set[str] = field(default_factory=set)
    caa_records: InitVar[Iterable[CAA]] = None

    def __post_init__(self, caa_records: Iterable[CAA]):
        caa_records = list(caa_records[:CAA_MAX_RECORDS]) if caa_records else []
        self.caa_records_str = [caa.to_text() for caa in caa_records]
        self.caa_tags = {caa.tag.decode("ascii") for caa in caa_records}

        for caa in caa_records:
            tag = caa.tag.decode("ascii", errors="replace")

            try:
                # For encoding, RFC8659 4.1 says tags are A-z0-9, so decoding as ascii is fine.
                # Only known tags are approved, so decoding with errors=replace is safe.
                # Value is "binary values", but currently all are probably ascii.
                validate_caa_record(caa.flags, tag, caa.value.decode("utf-8"))
            except CAAParseError as cpe:
                self.errors.append(TranslatableTechTableItem(cpe.msg_id, cpe.context))
            except UnicodeDecodeError:
                self.errors.append(
                    TranslatableTechTableItem(
                        "invalid-property-encoding",
                        {
                            "property_name": tag,
                        },
                    )
                )

        missing_tags = CAA_TAGS_REQUIRED - self.caa_tags
        for tag in missing_tags:
            self.errors.append(TranslatableTechTableItem(CAA_MSGID_INSUFFICIENT_POLICY, {"property_tag": tag}))

    @property
    def score(self) -> int:
        return scoring.CAA_GOOD if self.caa_found and not self.errors else scoring.CAA_BAD


def retrieve_parse_caa(target_domain: str) -> CAAEvaluation:
    """
    Retrieve and parse the CAA record(s) for a given domain.
    Looks up the DNS tree if needed, always returns a CAAEvaluation with results.
    """
    try:
        canonical_name, rrset = dns_resolve_caa(target_domain)
    except (NoNameservers, NoAnswer, NXDOMAIN, LifetimeTimeout, dns.name.EmptyLabel):
        return CAAEvaluation(caa_found=False)

    return CAAEvaluation(caa_found=True, canonical_name=canonical_name, caa_records=rrset)
