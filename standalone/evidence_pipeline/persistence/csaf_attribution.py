"""Verify one persisted advisory receipt by reconstructing its source projection."""

import hashlib
import json
from datetime import date, datetime
from decimal import Decimal

from psycopg2 import sql
from standalone.evidence_pipeline.contracts import SourceScope
from standalone.evidence_pipeline.parsing.csaf import parse_csaf
from standalone.evidence_pipeline.parsing.csaf_records import normalize_csaf
from standalone.evidence_pipeline.parsing.devices import stable_id

KEYS = {
    "advisories": ("id",),
    "recommendations": ("id",),
    "patches": ("id",),
    "patch_vulnerabilities": ("id",),
    "advisory_cves": ("advisory_id", "cve_id", "receipt_id"),
    "recommendation_cves": ("recommendation_id", "cve_id", "receipt_id"),
    "recommendation_patches": ("recommendation_id", "patch_id", "receipt_id"),
}


def key(table, row):
    values = tuple(row[column] for column in KEYS[table])
    return values[0] if len(values) == 1 else values


def verify_advisory_receipt(cursor, source, revision, receipt, claim):
    from standalone.evidence_pipeline.persistence.attribution import require

    require(
        source["source_name"] == "MSRC"
        and source["input_kind"] == "advisories"
        and source["tenant_id"] is None,
        "Invalid advisory source",
    )
    digest = hashlib.sha256(claim.encode()).hexdigest()
    require(
        revision["connection_id"] == source["id"]
        and revision["content_hash"] == digest
        and revision["id"]
        == stable_id(
            "public-revision", source["id"], revision["source_record_id"], digest
        )
        and receipt["source_revision_id"] == revision["id"]
        and receipt["id"]
        == stable_id(
            "public-receipt", revision["id"], receipt["collection_attempt_id"]
        ),
        "Advisory claim or receipt identity changed",
    )
    document = json.loads(claim)
    require(document.get("adapter") == "msrc-csaf-v1", "Unknown advisory adapter")
    raw = dict(document["source_document"])
    raw["vulnerabilities"] = [document["source_vulnerability"]]
    scope = SourceScope(
        source["id"],
        "MSRC",
        "advisories",
        source["scope_reference"],
        revision["origin"],
        revision["licence_or_provenance"],
    )
    feed = parse_csaf(json.dumps(raw).encode(), scope=scope)
    records = list(normalize_csaf(feed))
    require(
        len(records) == 1
        and records[0].cve_id == revision["source_record_id"]
        and records[0].claim == claim,
        "Advisory projection disagrees with retained source",
    )
    expected = {table: {} for table in KEYS}
    for table, row in records[0].evidence_rows(receipt["id"]):
        identity = key(table, row)
        require(identity not in expected[table], "Duplicate advisory projection")
        expected[table][identity] = row
    for table, wanted in expected.items():
        cursor.execute(
            sql.SQL(
                "SELECT to_jsonb(t)::text FROM evidence.{} t WHERE receipt_id=%s"
            ).format(sql.Identifier(table)),
            (receipt["id"],),
        )
        actual = {}
        for (text,) in cursor.fetchall():
            row = json.loads(text, parse_float=Decimal)
            identity = key(table, row)
            require(identity not in actual, "Duplicate stored advisory projection")
            actual[identity] = row
        require(set(actual) == set(wanted), "Missing or extra advisory projection")
        for identity, row in wanted.items():
            stored = actual[identity]
            for column, value in row.items():
                if isinstance(value, datetime) and isinstance(stored.get(column), str):
                    stored[column] = datetime.fromisoformat(stored[column])
                elif isinstance(value, date) and isinstance(stored.get(column), str):
                    stored[column] = date.fromisoformat(stored[column])
            require(
                all(stored.get(k) == v for k, v in row.items())
                and all(v is None for k, v in stored.items() if k not in row),
                "Advisory projection changed",
            )
    return {table: set(rows) for table, rows in expected.items()}
