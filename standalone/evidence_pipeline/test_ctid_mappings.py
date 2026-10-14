"""Synthetic explicit mappings without derived domains, names or relationships."""

import csv
from dataclasses import replace
import io
from uuid import uuid4

import pytest

from standalone.evidence_pipeline.parsing import ctid_mappings as source
from .contracts import SourceScope


def scope():
    return SourceScope(
        str(uuid4()),
        "CTID",
        "cve_mappings",
        source.URL,
        "synthetic",
        "TriageMate generated synthetic CTID mapping fixture",
    )


def payload(rows=None):
    output = io.StringIO(newline="")
    headers = ["CVE ID", *source.CATEGORIES, "Phase"]
    writer = csv.DictWriter(output, fieldnames=headers)
    writer.writeheader()
    for changes in rows if rows is not None else [{}]:
        row = dict.fromkeys(headers, "")
        row.update(
            {
                "CVE ID": "CVE-2099-1234",
                "Primary Impact": "T1059; T1059.001",
                "Exploitation Technique": "T1059",
                "Phase": "Synthetic phase",
            }
        )
        row.update(changes)
        writer.writerow(row)
    return output.getvalue().encode()


def test_mapping_category_and_source_phase_are_preserved():
    raw = payload()
    feed = source.parse_ctid(raw, scope=scope())
    record = feed.records[0]
    assert record.source_record_id == "CVE-2099-1234" and record.cve_ids == (
        record.cve_id,
    )
    assert record.mappings == (
        ("Primary Impact", "T1059"),
        ("Primary Impact", "T1059.001"),
        ("Exploitation Technique", "T1059"),
    )
    assert record.raw_rows[0]["Phase"] == "Synthetic phase" and feed.raw_payload == raw


def test_duplicate_cve_rows_preserve_variants_and_unmapped_cves():
    record = source.parse_ctid(
        payload([{}, {"Phase": "Other synthetic phase"}]), scope=scope()
    ).records[0]
    assert len(record.raw_rows) == 2 and len(record.mappings) == 3
    row = {category: "" for category in source.CATEGORIES}
    record = source.parse_ctid(payload([row]), scope=scope()).records[0]
    assert not record.mappings and record.cve_ids == ("CVE-2099-1234",)


def test_invalid_cve_rejects_whole_feed():
    with pytest.raises(ValueError):
        source.parse_ctid(payload([{}, {"CVE ID": "not-a-cve"}]), scope=scope())


@pytest.mark.parametrize("token", ["T123", "T1059/../x", "T1059.1234", "T1036."])
def test_unresolved_technique_tokens_are_preserved_without_repair(token):
    record = source.parse_ctid(
        payload([{"Primary Impact": token}]), scope=scope()
    ).records[0]
    assert record.unresolved_mappings == (("Primary Impact", token),)
    assert ("Primary Impact", token) not in record.mappings
    assert record.raw_rows[0]["Primary Impact"] == token


@pytest.mark.parametrize(
    "raw",
    [b"", b"CVE ID,Phase\nCVE-2099-1234,test\n", b"CVE ID,CVE ID\n", b"\xff", b"\0"],
)
def test_bad_wire_structure_rejected(raw):
    with pytest.raises(ValueError):
        source.parse_ctid(raw, scope=scope())


def test_wrong_scope_or_tenant_rejected():
    for changes in (
        dict(source="MITRE"),
        dict(scope_reference="https://example.invalid"),
        dict(tenant_id=str(uuid4())),
    ):
        with pytest.raises(ValueError):
            source.parse_ctid(payload(), scope=replace(scope(), **changes))
