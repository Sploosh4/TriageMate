"""OSV normalization keeps native identity and aliases separate."""

from decimal import Decimal
import json

from standalone.evidence_pipeline.source_json import encode_source_records
from standalone.evidence_pipeline.parsing.osv import parse_osv
from standalone.evidence_pipeline.parsing.public_records import normalize_public
from .test_osv import document, scope
from .test_public_records import RECEIPT


def normalize(raw):
    return next(normalize_public(parse_osv(encode_source_records(raw), scope=scope())))


def test_native_advisory_is_not_replaced_by_first_cve_alias():
    raw = document()
    record = normalize(raw)
    assert record.source_record_id == raw["id"]
    assert record.cve_ids == tuple(raw["aliases"])
    rows = list(record.evidence_rows(RECEIPT))
    assert len(rows) == 4
    assert all(
        row["advisory_id"] == raw["id"] and "cve_id" not in row for _, row in rows
    )
    assert [
        (r["alias_index"], r["alias_id"]) for table, r in rows if table == "osv_aliases"
    ] == list(enumerate(raw["aliases"]))
    package = rows[-1][1]
    assert (
        package["ecosystem"] == "PyPI"
        and package["package_name"] == "synthetic-package"
    )
    assert json.loads(package["source_fields"]) == raw["affected"][0]


def test_unaliased_withdrawn_record_has_no_invented_cve_or_package():
    raw = dict(
        id="x_synthetic-only",
        modified="2026-09-14T01:00:00Z",
        withdrawn="2026-09-14T02:00:00Z",
    )
    record = normalize(raw)
    assert record.cve_ids == ()
    rows = list(record.evidence_rows(RECEIPT))
    assert len(rows) == 1 and rows[0][1]["withdrawn_text"] == raw["withdrawn"]


def test_unknown_values_precision_and_receipt_identity_survive():
    raw = document()
    raw["database_specific"] = {
        "source_number": Decimal("0.123456789012345678901"),
        "flag": False,
    }
    record = normalize(raw)
    assert (
        json.loads(json.loads(record.claim)["source_document"], parse_float=Decimal)
        == raw
    )
    assert normalize(dict(reversed(list(raw.items())))) == record
    first = list(record.evidence_rows(RECEIPT))
    second = list(record.evidence_rows("10000000-0000-4000-8000-000000000023"))
    assert all(a[1]["id"] != b[1]["id"] for a, b in zip(first, second, strict=True))
