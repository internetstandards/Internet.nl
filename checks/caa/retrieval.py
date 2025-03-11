from dataclasses import dataclass, field, InitVar
from typing import Optional, Iterable

from dns.rdtypes.ANY.CAA import CAA
from dns.resolver import NoAnswer, NXDOMAIN, LifetimeTimeout, NoNameservers

from checks import scoring
from checks.caa.parser import validate_caa_record, CAAParseError
from checks.resolver import dns_resolve_caa
from checks.tasks.shared import TranslatableTechTableItem

CAA_TAGS_REQUIRED = {"issue"}
CAA_MAX_RECORDS = 1000


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
        self.cca_tags = {caa.tag.decode("ascii") for caa in caa_records}

        for caa in caa_records:
            try:
                validate_caa_record(caa.flags, caa.tag.decode("ascii"), caa.value.decode("ascii"))
            except CAAParseError as cpe:
                self.errors.append(TranslatableTechTableItem(cpe.msg_id, cpe.context))

        missing_tags = CAA_TAGS_REQUIRED - self.caa_tags
        for tag in missing_tags:
            self.errors.append(TranslatableTechTableItem("missing_required_tag", {"tag": tag}))

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
    except (NoAnswer, NXDOMAIN, LifetimeTimeout, NoNameservers):
        return CAAEvaluation(caa_found=False)

    return CAAEvaluation(caa_found=True, canonical_name=canonical_name, caa_records=rrset)
