"""Product-scoped update recipes cannot invent cross-product replacement or CVE links."""

from uuid import uuid4
import json
import pytest

from standalone.evidence_pipeline.parsing.cvrf_records import normalize_cvrf_updates
from .test_cvrf_updates import document, parse


def rows(value):
    (record,) = normalize_cvrf_updates(parse(value))
    return record, list(record.evidence_rows(str(uuid4())))


def test_patch_identity_reuse_is_receipt_local_and_preserves_links(monkeypatch):
    from standalone.evidence_pipeline.parsing import cvrf_records
    from standalone.evidence_pipeline.parsing.csaf_records import RowReference

    record = cvrf_records.UpdateRecord(
        "CVE-2099-9999999",
        "synthetic",
        "synthetic",
        (
            ("patches", (("source_patch_id", "KB9999991"),)),
            ("patch_applicability", (("patch_id", RowReference(0)),)),
            ("patch_vulnerabilities", (("patch_id", RowReference(0)),)),
            (
                "patch_replacements",
                (
                    ("patch_id", RowReference(0)),
                    ("superseded_patch_id", RowReference(0)),
                ),
            ),
        ),
    )
    original = cvrf_records.stable_id
    calls = []

    def counted(*parts):
        calls.append(parts)
        return original(*parts)

    monkeypatch.setattr(cvrf_records, "stable_id", counted)
    first, second = str(uuid4()), str(uuid4())
    before = list(record.evidence_rows(first))
    after = list(record.evidence_rows(second))
    assert len(calls) == 2 * len(record.rows)
    for receipt, values in ((first, before), (second, after)):
        patch = original("public-observation", receipt, "patches", "0")
        assert values[0][1]["id"] == patch
        assert all(row["patch_id"] == patch for _, row in values[1:])
        assert values[-1][1]["superseded_patch_id"] == patch
        assert all(row["receipt_id"] == receipt for _, row in values)
    assert before[0][1]["id"] != after[0][1]["id"]


@pytest.mark.parametrize("reference", [-1, 1, 2, True, 0.0, "0"])
def test_cached_patch_reference_cannot_bypass_index_checks(reference):
    from standalone.evidence_pipeline.parsing.cvrf_records import UpdateRecord
    from standalone.evidence_pipeline.parsing.csaf_records import RowReference

    record = UpdateRecord(
        "CVE-2099-9999999",
        "synthetic",
        "synthetic",
        (
            ("patches", ()),
            ("patch_replacements", (("patch_id", RowReference(reference)),)),
        ),
    )
    with pytest.raises(ValueError, match="Invalid CVRF patch relationship"):
        list(record.evidence_rows(str(uuid4())))


def test_cached_relationship_requires_a_patch_row():
    from standalone.evidence_pipeline.parsing.cvrf_records import UpdateRecord
    from standalone.evidence_pipeline.parsing.csaf_records import RowReference

    record = UpdateRecord(
        "CVE-2099-9999999",
        "synthetic",
        "synthetic",
        (
            ("patch_applicability", ()),
            ("patch_replacements", (("patch_id", RowReference(0)),)),
        ),
    )
    with pytest.raises(ValueError, match="Invalid CVRF patch relationship"):
        list(record.evidence_rows(str(uuid4())))


def test_new_fix_is_cve_linked_but_superseded_reference_is_not():
    record, values = rows(document())
    patches = {
        row["source_patch_id"]: row for table, row in values if table == "patches"
    }
    links = [row for table, row in values if table == "patch_vulnerabilities"]
    assert len(links) == 1 and links[0]["patch_id"] == patches["KB9999991"]["id"]
    (relationship,) = [row for table, row in values if table == "patch_replacements"]
    assert relationship["superseded_patch_id"] == patches["KB9999990"]["id"]
    claim = json.loads(record.claim)
    assert len(claim["record"]["updates"]) == 2
    assert not {"device_missing_patches", "vulnerability_findings"} & {
        table for table, _ in values
    }


def test_same_kb_on_two_products_has_separate_scoped_edges():
    value = document()
    value["Vulnerability"][0]["Remediations"][0]["ProductID"] = ["p1", "p2"]
    _, values = rows(value)
    patches = {row["id"]: row for table, row in values if table == "patches"}
    edges = [row for table, row in values if table == "patch_replacements"]
    assert len(edges) == 2
    for edge in edges:
        assert (
            patches[edge["patch_id"]]["product_names"]
            == patches[edge["superseded_patch_id"]]["product_names"]
        )


def test_fixed_build_is_retained_without_inventing_a_version_range():
    record, values = rows(document())
    (applicable,) = [row for table, row in values if table == "patch_applicability"]
    assert (
        applicable["version_expression"] is None and applicable["architecture"] is None
    )
    assert json.loads(record.claim)["record"]["updates"][0]["fixed_build"] == "1.2.3.4"


def test_no_structured_fix_retains_source_claim_without_patch_rows():
    value = document()
    value["Vulnerability"][0]["Remediations"] = [
        {"Type": 0, "ProductID": ["p1"], "Description": {"Value": "Synthetic advice"}}
    ]
    record, values = rows(value)
    assert values == []
    claim = json.loads(record.claim)
    assert claim["source_vulnerability"] == value["Vulnerability"][0]
    assert claim["record"]["updates"] == []


def test_source_claim_can_reconstruct_identical_projection_and_hash():
    record, _ = rows(document())
    claim = json.loads(record.claim)
    reconstructed = {
        **claim["source_document"],
        "Vulnerability": [claim["source_vulnerability"]],
    }
    (again,) = normalize_cvrf_updates(parse(reconstructed))
    assert again == record
    receipt = str(uuid4())
    assert list(again.evidence_rows(receipt)) == list(record.evidence_rows(receipt))


def test_repeated_references_and_unnamed_remediation_reconstruct_exactly():
    value = document()
    remedies = value["Vulnerability"][0]["Remediations"]
    remedies[0]["ProductID"] = ["p1", "p1"]
    remedies[1]["Description"] = {}
    record, _ = rows(value)
    claim = json.loads(record.claim)
    reconstructed = {
        **claim["source_document"],
        "Vulnerability": [claim["source_vulnerability"]],
    }
    (again,) = normalize_cvrf_updates(parse(reconstructed))
    assert again == record


def test_projection_work_splits_batches_without_rejecting_large_records():
    from types import SimpleNamespace
    from standalone.evidence_pipeline.persistence.public_store import _batches

    records = [
        SimpleNamespace(claim="synthetic", rows=(None,) * size)
        for size in (300, 300, 900, 20)
    ]
    batches = list(_batches(iter(records)))
    assert list(map(len, batches)) == [1, 1, 1, 1]
    assert [r for batch in batches for r in batch] == records


def test_incremental_claim_encoding_preserves_legacy_bytes_and_hash():
    from dataclasses import asdict
    from decimal import Decimal
    import hashlib
    from standalone.evidence_pipeline.parsing.csaf_records import RowReference
    from standalone.evidence_pipeline.parsing.cvrf_records import update_claim
    from standalone.evidence_pipeline.parsing.public_records import canonical

    value = document()
    value["Vulnerability"][0]["Remediations"][0]["Extension"] = {
        "text": "é漢😀",
        "decimal": Decimal("0.100"),
        "zero": 0,
        "false": False,
    }
    # Feed parsing already produces validated records; exercise direct nested
    # values too so canonical Decimal/Unicode handling cannot change silently.
    from standalone.evidence_pipeline.parsing.cvrf_updates import parse_cvrf_document
    from .test_cvrf_updates import source

    records = parse_cvrf_document(value, scope=source())
    projection = [
        ("patches", (("id", "synthetic"),)),
        ("patch_replacements", (("patch_id", RowReference(0)),)),
    ]
    source_document = {"Extension": {"decimal": Decimal("0.10")}}
    for selected in ((), records):
        expected = canonical(
            {
                "adapter": "msrc-cvrf-updates-v1",
                "record": {
                    "cve_id": "CVE-2026-12345",
                    "updates": [asdict(r) for r in selected],
                },
                "source_document": source_document,
                "source_vulnerability": value["Vulnerability"][0],
                "projection": [
                    (
                        table,
                        [
                            (
                                key,
                                {"row_reference": v.index}
                                if isinstance(v, RowReference)
                                else v,
                            )
                            for key, v in values
                        ],
                    )
                    for table, values in projection
                ],
            }
        )
        actual = update_claim(
            "CVE-2026-12345",
            selected,
            projection,
            source_document,
            value["Vulnerability"][0],
        )
        assert actual == expected
        assert (
            hashlib.sha256(actual.encode()).hexdigest()
            == hashlib.sha256(expected.encode()).hexdigest()
        )


@pytest.mark.parametrize(
    "native_id",
    [
        "ADV160001",
        "CVE-2022-2601-M",
        "CVE-2023-32002 - M",
        "CVE-2023-38039 mariner - do not use this one",
    ],
)
def test_native_advisory_preserves_patch_claims_without_cve_links(native_id):
    value = document()
    value["Vulnerability"][0]["CVE"] = native_id
    record, values = rows(value)
    assert record.source_record_id == native_id
    assert record.cve_id is None and record.cve_ids == ()
    assert {table for table, _ in values} == {
        "patches",
        "patch_applicability",
        "patch_replacements",
    }
    claim = json.loads(record.claim)
    assert claim["adapter"] == "msrc-cvrf-advisory-v1"
    assert claim["record"]["native_id"] == native_id
    assert "cve_id" not in claim["record"]
    assert claim["source_vulnerability"] == value["Vulnerability"][0]
    reconstructed = dict(
        claim["source_document"], Vulnerability=[claim["source_vulnerability"]]
    )
    assert list(normalize_cvrf_updates(parse(reconstructed))) == [record]
