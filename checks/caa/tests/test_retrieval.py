from dns.rdataclass import RdataClass
from dns.rdatatype import RdataType
from dns.rdtypes.ANY.CAA import CAA

from checks.caa.retrieval import CAAEvaluation
from checks.tasks.shared import TranslatableTechTableItem


def test_caa_evaluation():
    caa_records = [CAA(RdataClass.IN, RdataType.CAA, 0, b"issue", b";")]
    evaluation = CAAEvaluation(caa_found=True, canonical_name="example.com", caa_records=caa_records)
    assert evaluation.errors == []
    assert evaluation.recommendations == []
    assert evaluation.caa_records_str == ['0 issue ";"']
    assert evaluation.caa_tags == {"issue"}

    caa_records = [
        CAA(RdataClass.IN, RdataType.CAA, 0, b"issuewild", b"\x08"),
        CAA(RdataClass.IN, RdataType.CAA, 0, b"unknown", b";"),
    ]
    evaluation = CAAEvaluation(caa_found=True, canonical_name="example.com", caa_records=caa_records)
    assert evaluation.errors == [
        TranslatableTechTableItem(
            "invalid-property-syntax",
            {
                "property_name": "issuewild",
                "property_value": "\x08",
                "invalid_character_position": 0,
                "invalid_character": "\x08",
            },
        ),
        TranslatableTechTableItem("invalid-unknown-property", {"property_tag": "unknown"}),
        TranslatableTechTableItem("missing-required-property-issue", {"property_tag": "issue"}),
    ]
    assert evaluation.caa_records_str == ['0 issuewild "\\008"', '0 unknown ";"']
    assert evaluation.caa_tags == {"issuewild", "unknown"}
