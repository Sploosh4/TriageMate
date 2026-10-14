"""Reconstruct source CVE JSON and verify every independently owned observation."""

from collections import defaultdict
from decimal import Decimal
import hashlib
import json

from psycopg2 import sql

from standalone.evidence_pipeline.contracts import SourceScope
from standalone.evidence_pipeline.parsing.cve_program import parse_cve_record
from standalone.evidence_pipeline.parsing.cve_records import normalize_cve_record
from standalone.evidence_pipeline.parsing.devices import stable_id

TABLES = ("cve_record_observations", "cve_contributions")


def verify_cve_inventory(cursor, verified):
    from standalone.evidence_pipeline.persistence.attribution import require

    for table in TABLES:
        cursor.execute("SELECT to_regclass(%s)", ("evidence." + table,))
        if cursor.fetchone()[0] is None:
            require(not verified.get(table), "Missing CVE evidence table")
            continue
        cursor.execute(
            sql.SQL("SELECT id::text FROM evidence.{}").format(sql.Identifier(table))
        )
        require(
            {row[0] for row in cursor.fetchall()} == verified.get(table, set()),
            "Unexplained CVE evidence",
        )


def verify_cve_receipt(cursor, source, revision, receipt, claim):
    from standalone.evidence_pipeline.persistence.attribution import require

    require(
        (source["source_name"], source["input_kind"])
        in {("CVE", "records"), ("CISA", "vulnrichment")}
        and source["tenant_id"] is None,
        "Invalid CVE source",
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
        "CVE claim or receipt identity changed",
    )
    document = json.loads(claim)
    require(document.get("adapter") == "cve-record-v1", "Unknown CVE adapter")
    scope = SourceScope(
        source["id"],
        source["source_name"],
        source["input_kind"],
        source["scope_reference"],
        revision["origin"],
        revision["licence_or_provenance"],
    )
    records = list(
        normalize_cve_record(
            parse_cve_record(document["source_document"].encode(), scope=scope)
        )
    )
    require(
        len(records) == 1
        and records[0].claim == claim
        and records[0].cve_id == revision["source_record_id"],
        "CVE projection disagrees with retained source",
    )
    expected = defaultdict(dict)
    for table, row in records[0].evidence_rows(receipt["id"]):
        for field in ("source_metadata", "source_fields"):
            if field in row:
                row[field] = json.loads(row[field], parse_float=Decimal)
        expected[table][row["id"]] = row
    for table in TABLES:
        cursor.execute(
            sql.SQL(
                "SELECT to_jsonb(t)::text FROM evidence.{} t WHERE receipt_id=%s"
            ).format(sql.Identifier(table)),
            (receipt["id"],),
        )
        stored = [
            json.loads(text, parse_float=Decimal) for (text,) in cursor.fetchall()
        ]
        require(
            len(stored) == len(expected[table])
            and {row["id"]: row for row in stored} == expected[table],
            "CVE projection changed or missing",
        )
    return {table: set(expected[table]) for table in TABLES}
