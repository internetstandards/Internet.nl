from unittest.mock import patch


from checks import scoring
from checks.hsts.evaluation import HSTSEvaluation, HSTS_MIN_MAX_AGE
from checks.tasks.shared import TranslatableTechTableItem

MOCK_PSL = [
    (["nl"], False),
    (["nl", "gov"], False),
    (["uk", "co"], False),
]


@patch("checks.hsts.evaluation.dmarc_get_public_suffix_list", return_value=MOCK_PSL)
def test_hsts_evaluation(mock_psl):
    # Valid HSTS with preload on apex domain on PSL
    evaluation = HSTSEvaluation(
        domain="example.gov.nl",
        hsts_policies=["max-age=31536000; includeSubDomains; preload"],
    )
    assert evaluation.hsts_enabled
    assert evaluation.errors == []
    assert evaluation.recommendations == []
    assert evaluation.directives == {"max-age": 31536000, "includesubdomains": True, "preload": True}
    assert evaluation.score == scoring.WEB_TLS_HSTS_GOOD

    # Valid but too short max-age -> recommendations & PARTIAL score
    evaluation = HSTSEvaluation(
        domain="example.nl",
        hsts_policies=["max-age=3600; includeSubDomains"],
    )
    assert evaluation.hsts_enabled
    assert evaluation.errors == []
    assert evaluation.recommendations == [
        TranslatableTechTableItem(
            "invalid-max-age-too-short",
            {"max_age": 3600, "min_max_age": HSTS_MIN_MAX_AGE},
        )
    ]
    assert evaluation.directives == {"max-age": 3600, "includesubdomains": True}
    assert evaluation.score == scoring.WEB_TLS_HSTS_PARTIAL

    # too short preload without includeSubDomains and on non-apex subdomain -> recommendations
    evaluation = HSTSEvaluation(
        domain="www.example.co.uk",
        hsts_policies=["max-age=31535999; preload"],
    )
    assert evaluation.hsts_enabled
    assert evaluation.errors == []
    assert evaluation.recommendations == [
        TranslatableTechTableItem(
            "invalid-max-age-too-short",
            {"max_age": 31535999, "min_max_age": HSTS_MIN_MAX_AGE},
        ),
        TranslatableTechTableItem("ineffective-preload-no-includesubdomains", {}),
        TranslatableTechTableItem(
            "ineffective-preload-too-short",
            {"max_age": 31535999, "min_max_age": HSTS_MIN_MAX_AGE},
        ),
        TranslatableTechTableItem(
            "ineffective-preload-no-apex", {"domain": "www.example.co.uk", "apex": "example.co.uk"}
        ),
    ]
    assert evaluation.directives == {"max-age": 31535999, "preload": True}
    assert evaluation.score == scoring.WEB_TLS_HSTS_PARTIAL

    # Invalid syntax -> BAD with error
    evaluation = HSTSEvaluation(
        domain="example.nl",
        hsts_policies=["\x08"],
    )
    assert not evaluation.hsts_enabled
    assert evaluation.errors == [
        TranslatableTechTableItem(
            "invalid-syntax",
            {
                "header_value": "\x08",
                "invalid_character_position": 0,
                "invalid_character": "\x08",
            },
        )
    ]
    assert not evaluation.recommendations
    assert not evaluation.directives
    assert evaluation.score == scoring.WEB_TLS_HSTS_BAD

    # First header invalid, second valid -> RFC 6797 Section 8.1 processes only first header
    evaluation = HSTSEvaluation(
        domain="example.nl",
        hsts_policies=["max-age=1; includeSubDomains=1", "max-age=31536000"],
    )
    assert not evaluation.hsts_enabled
    assert evaluation.errors == [
        TranslatableTechTableItem(
            "invalid-includesubdomains-value",
            {"directive_value": "1"},
        ),
    ]
    assert evaluation.recommendations == [TranslatableTechTableItem("multiple-headers", {})]
    assert not evaluation.directives
    assert evaluation.score == scoring.WEB_TLS_HSTS_BAD
