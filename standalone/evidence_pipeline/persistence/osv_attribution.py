"""Reconstruct OSV records without merging native identity and CVE aliases."""

from collections import defaultdict
from decimal import Decimal
import hashlib
import json

from psycopg2 import sql

from standalone.evidence_pipeline.contracts import SourceScope
from standalone.evidence_pipeline.parsing.osv import parse_osv
from standalone.evidence_pipeline.parsing.osv_records import normalize_osv
from standalone.evidence_pipeline.parsing.devices import stable_id

TABLES = ("osv_advisory_observations", "osv_aliases", "osv_affected_packages")


def verify_osv_inventory(cursor, verified):
    from standalone.evidence_pipeline.persistence.attribution import require

    for table in TABLES:
        cursor.execute("SELECT to_regclass(%s)", ("evidence." + table,))
        if cursor.fetchone()[0] is None:
            require(not verified.get(table), "Missing OSV evidence table")
            continue
        cursor.execute(
            sql.SQL("SELECT id::text FROM evidence.{}").format(sql.Identifier(table))
        )
        require(
            {row[0] for row in cursor.fetchall()} == verified.get(table, set()),
            "Unexplained OSV evidence",
        )


def verify_osv_receipt(cursor, source, revision, receipt, claim):
    from standalone.evidence_pipeline.persistence.attribution import require

    require(
        (source["source_name"], source["input_kind"])
        in {("OSV", "advisories"), ("GitHub", "advisories"), ("Ubuntu", "advisories")}
        and source["tenant_id"] is None,
        "Invalid OSV source",
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
        "OSV claim or receipt identity changed",
    )
    document = json.loads(claim)
    require(document.get("adapter") == "osv-record-v1", "Unknown OSV adapter")
    scope = SourceScope(
        source["id"],
        source["source_name"],
        source["input_kind"],
        source["scope_reference"],
        revision["origin"],
        revision["licence_or_provenance"],
    )
    parser = parse_osv
    if scope.source == "GitHub":
        from standalone.evidence_pipeline.parsing.github_advisories import (
            parse_github_advisory,
        )

        parser = parse_github_advisory
    if scope.source == "Ubuntu":
        from standalone.evidence_pipeline.parsing.ubuntu_advisories import parse_ubuntu

        parser = parse_ubuntu
    records = list(
        normalize_osv(parser(document["source_document"].encode(), scope=scope))
    )
    require(
        len(records) == 1
        and records[0].claim == claim
        and records[0].source_record_id == revision["source_record_id"],
        "OSV projection disagrees with retained source",
    )
    expected = defaultdict(dict)
    for table, row in records[0].evidence_rows(receipt["id"]):
        if "source_fields" in row:
            row["source_fields"] = json.loads(row["source_fields"], parse_float=Decimal)
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
            "OSV projection changed or missing",
        )
    return {table: set(expected[table]) for table in TABLES}, set(records[0].cve_ids)
