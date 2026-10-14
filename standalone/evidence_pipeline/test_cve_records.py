"""Synthetic evidence preserves contributor conflicts and rejected records."""

import copy
from decimal import Decimal
import json

from standalone.evidence_pipeline.source_json import encode_source_records

from standalone.evidence_pipeline.parsing.cve_program import parse_cve_record
from standalone.evidence_pipeline.parsing.public_records import normalize_public
from .test_cve_program import document, scope
from .test_public_records import RECEIPT


def normalized(value):
    feed = parse_cve_record(encode_source_records(value), scope=scope())
    return next(normalize_public(feed))


def test_conflicting_contributors_keep_identity_and_independent_values():
    value = document()
    containers = value["containers"]
    containers["cna"]["metrics"] = [{"cvssV3_1": {"baseScore": Decimal("9.8")}}]
    containers["adp"][0]["metrics"] = [{"cvssV3_1": {"baseScore": Decimal("7.5")}}]
    # Even repeated organization IDs cannot silently collapse contributions.
    containers["adp"].append(copy.deepcopy(containers["adp"][0]))
    containers["adp"][1]["metrics"][0]["cvssV3_1"]["baseScore"] = Decimal("8.1")
    result = normalized(value)
    rows = list(result.evidence_rows(RECEIPT))
    assert len(rows) == 4 and len({row["id"] for _, row in rows}) == 4
    contributions = [row for table, row in rows if table == "cve_contributions"]
    assert [(r["contributor_kind"], r["contributor_index"]) for r in contributions] == [
        ("cna", 0),
        ("adp", 0),
        ("adp", 1),
    ]
    assert [
        json.loads(r["source_fields"], parse_float=Decimal)["metrics"][0]["cvssV3_1"][
            "baseScore"
        ]
        for r in contributions
    ] == [Decimal("9.8"), Decimal("7.5"), Decimal("8.1")]
    assert all(row["cve_id"] == value["cveMetadata"]["cveId"] for _, row in rows)


def test_source_extensions_and_numbers_survive_and_object_order_is_irrelevant():
    value = document()
    value["x_synthetic"] = {
        "metric": Decimal("0.1234567890123456789012345"),
        "known": False,
    }
    first = normalized(value)
    claim = json.loads(first.claim)
    assert json.loads(claim["source_document"], parse_float=Decimal) == value
    assert normalized(dict(reversed(list(value.items())))) == first
    value["x_synthetic"]["known"] = True
    assert normalized(value).content_hash != first.content_hash


def test_rejection_stays_queryable_without_fabricated_active_facts():
    value = document()
    value["cveMetadata"]["state"] = "REJECTED"
    cna = value["containers"]["cna"]
    value["containers"] = {
        "cna": {
            "providerMetadata": cna["providerMetadata"],
            "rejectedReasons": [{"lang": "en", "value": "Synthetic rejection"}],
            "replacedBy": ["CVE-2099-54321"],
        }
    }
    rows = list(normalized(value).evidence_rows(RECEIPT))
    assert rows[0][1]["record_state"] == "REJECTED"
    assert [table for table, _ in rows] == [
        "cve_record_observations",
        "cve_contributions",
    ]
    assert json.loads(rows[1][1]["source_fields"])["replacedBy"] == ["CVE-2099-54321"]


def test_receipts_have_distinct_rows_but_same_immutable_claim():
    record = normalized(document())
    first = list(record.evidence_rows(RECEIPT))
    second = list(record.evidence_rows("10000000-0000-4000-8000-000000000022"))
    assert all(a[1]["id"] != b[1]["id"] for a, b in zip(first, second, strict=True))
    assert list(record.evidence_rows(RECEIPT)) == first
