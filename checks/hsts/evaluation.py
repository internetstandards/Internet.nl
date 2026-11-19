from dataclasses import dataclass, field, InitVar
from celery.exceptions import SoftTimeLimitExceeded

from checks import scoring
from checks.hsts.parser import parse_hsts_header, HSTSParseError
from checks.tasks.mail import dmarc_find_organizational_domain, dmarc_get_public_suffix_list
from checks.tasks.shared import TranslatableTechTableItem

HSTS_MIN_MAX_AGE = 31536000  # 1 year in seconds
# keys are in lower case
HSTS_MAX_AGE = "max-age"
HSTS_INCLUDESUBDOMAINS = "includesubdomains"
HSTS_PRELOAD = "preload"


# this should move to shared code
def get_apex(domain: str) -> bool:
    public_suffix_list = dmarc_get_public_suffix_list()
    if not public_suffix_list:
        # We don't have the public suffix list.
        # Raise SoftTimeLimitExceeded to easily fail the test.
        raise SoftTimeLimitExceeded

    return dmarc_find_organizational_domain(domain, public_suffix_list)


@dataclass
class HSTSEvaluation:
    """
    The evaluation of a set of HSTS headers.
    """

    errors: list[TranslatableTechTableItem] = field(default_factory=list)
    recommendations: list[TranslatableTechTableItem] = field(default_factory=list)
    directives: dict[str, int | bool | str] = field(default_factory=dict)
    hsts_enabled: bool = field(init=False, default=False)
    domain: InitVar[str | None] = None
    hsts_policies: list[str] = field(default_factory=list)

    def __post_init__(self, domain: str | None):
        if len(self.hsts_policies) > 1:
            self.recommendations.append(TranslatableTechTableItem("multiple-headers", {}))

        # RFC 6797 Section 8.1: UAs only process the first HSTS header
        if self.hsts_policies:
            first_hsts = self.hsts_policies[0]
            try:
                parsed_directives, parser_recs = parse_hsts_header(first_hsts)
            except HSTSParseError as hpe:
                self.errors.append(hpe.to_translatable_tech_table_item())
                return

            self.directives = parsed_directives
            self.hsts_enabled = True
            self.recommendations.extend(rec.to_translatable_tech_table_item() for rec in parser_recs)

            if self.directives[HSTS_MAX_AGE] < HSTS_MIN_MAX_AGE:
                self.recommendations.append(
                    TranslatableTechTableItem(
                        "invalid-max-age-too-short",
                        {"max_age": self.directives[HSTS_MAX_AGE], "min_max_age": HSTS_MIN_MAX_AGE},
                    )
                )
            if self.directives.get(HSTS_PRELOAD) is True:
                if HSTS_INCLUDESUBDOMAINS not in self.directives:
                    self.recommendations.append(
                        TranslatableTechTableItem("ineffective-preload-no-includesubdomains", {})
                    )
                if self.directives[HSTS_MAX_AGE] < HSTS_MIN_MAX_AGE:
                    self.recommendations.append(
                        TranslatableTechTableItem(
                            "ineffective-preload-too-short",
                            {"max_age": self.directives[HSTS_MAX_AGE], "min_max_age": HSTS_MIN_MAX_AGE},
                        )
                    )
                if domain:
                    normalized = domain.strip().rstrip(".").lower()
                    apex = get_apex(normalized)
                    if normalized != apex:
                        self.recommendations.append(
                            TranslatableTechTableItem(
                                "ineffective-preload-no-apex",
                                {"domain": normalized, "apex": apex},
                            )
                        )

    @property
    def score(self) -> int:
        if self.hsts_enabled:
            if self.directives[HSTS_MAX_AGE] >= HSTS_MIN_MAX_AGE:
                return scoring.WEB_TLS_HSTS_GOOD
            return scoring.WEB_TLS_HSTS_PARTIAL
        return scoring.WEB_TLS_HSTS_BAD
