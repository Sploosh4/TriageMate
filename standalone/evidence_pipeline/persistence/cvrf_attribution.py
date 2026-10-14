"""Reconstruct CVRF receipts and require exact source-derived rows and identities."""

import hashlib
import json
from collections import defaultdict
from decimal import Decimal
from uuid import uuid4

from psycopg2 import sql, extensions
from standalone.evidence_pipeline.source_json import encode_source_records
from standalone.evidence_pipeline.contracts import SourceScope
from standalone.evidence_pipeline.parsing.cvrf_updates import parse_cvrf_updates
from standalone.evidence_pipeline.parsing.cvrf_records import normalize_cvrf_updates
from standalone.evidence_pipeline.parsing.devices import stable_id

TABLES = (
    "patches",
    "patch_vulnerabilities",
    "patch_applicability",
    "patch_replacements",
)

# One indexed read per receipt, preserving each table's complete payload and
# separate map/batch checks. No aggregation can hide duplicate or missing rows.
RECEIPT_ROWS = sql.SQL(" UNION ALL ").join(
    [
        sql.SQL(
            "SELECT {}::text,to_jsonb(t) FROM evidence.{} t WHERE receipt_id=%s"
        ).format(sql.Literal(table), sql.Identifier(table))
        for table in TABLES
    ]
    + [
        sql.SQL(
            "SELECT 'map'::text,jsonb_build_array(row_index,table_name,entity_id::text) "
            "FROM evidence_pipeline.cvrf_projection WHERE receipt_id=%s"
        ),
        sql.SQL(
            "SELECT 'batch'::text,to_jsonb(row_count) "
            "FROM evidence_pipeline.cvrf_batches WHERE receipt_id=%s"
        ),
    ]
)


class ReceiptRowsReader:
    """Reuse a query plan, never receipt contents or verification results.

    Preparation is lazy so older databases without CVRF tables remain auditable.
    The statement belongs only to this audit's database session.
    """

    def __init__(self, cursor):
        self.cursor = cursor
        self.name = sql.Identifier("tm_cvrf_audit_" + uuid4().hex)
        self.prepared = False

    def __enter__(self):
        return self

    def read(self, receipt_id):
        if not self.prepared:
            query = RECEIPT_ROWS.as_string(self.cursor).replace("%s", "$1")
            self.cursor.execute(
                sql.SQL("PREPARE {} (uuid) AS ").format(self.name) + sql.SQL(query)
            )
            self.prepared = True
        self.cursor.execute(sql.SQL("EXECUTE {} (%s)").format(self.name), (receipt_id,))
        return self.cursor

    def __exit__(self, *exc):
        # An aborted transaction cannot execute cleanup; its owning audit closes
        # the session. Do not mask the original database error in that case.
        if self.prepared and self.cursor.connection.get_transaction_status() != (
            extensions.TRANSACTION_STATUS_INERROR
        ):
            self.cursor.execute(sql.SQL("DEALLOCATE {}").format(self.name))
        self.prepared = False


def source_numbers(value):
    if isinstance(value, dict):
        if set(value) == {"decimal"}:
            return Decimal(value["decimal"])
        return {key: source_numbers(item) for key, item in value.items()}
    if isinstance(value, list):
        return [source_numbers(item) for item in value]
    return value


class UpdateReconstruction:
    """Reuse only the last exact source reconstruction within one verification.

    No receipt/projection result is cached. The complete claim and all scope
    values consumed by the parser must match; a changed source is reconstructed.
    Retaining one record bounds this cache by individual-record size.
    """

    def __init__(self):
        self.key = self.record = None

    def read(self, source, revision, claim):
        key = (
            source["id"],
            source["scope_reference"],
            revision["origin"],
            revision["licence_or_provenance"],
            revision["source_record_id"],
            claim,
        )
        if key != self.key:
            record = reconstruct_update(source, revision, claim)
            self.key, self.record = key, record
        return self.record


def verify_update_receipt(
    cursor, source, revision, receipt, claim, *, reconstruction=None, row_reader=None
):
    from standalone.evidence_pipeline.persistence.attribution import require

    require(
        (source["source_name"], source["input_kind"]) == ("MSRC", "security_updates")
        and source["tenant_id"] is None,
        "Invalid CVRF source",
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
        "CVRF claim or receipt identity changed",
    )
    record = (
        reconstruct_update(source, revision, claim)
        if reconstruction is None
        else reconstruction.read(source, revision, claim)
    )
    return verify_update_rows(cursor, receipt, record, row_reader=row_reader)


def reconstruct_update(source, revision, claim):
    from standalone.evidence_pipeline.persistence.attribution import require

    document = json.loads(claim)
    require(
        document.get("adapter") in {"msrc-cvrf-updates-v1", "msrc-cvrf-advisory-v1"},
        "Unknown CVRF adapter",
    )
    raw = source_numbers(
        {
            **document["source_document"],
            "Vulnerability": document.get(
                "source_variants", [document["source_vulnerability"]]
            ),
        }
    )
    scope = SourceScope(
        source["id"],
        "MSRC",
        "security_updates",
        source["scope_reference"],
        revision["origin"],
        revision["licence_or_provenance"],
    )
    records = list(
        normalize_cvrf_updates(
            parse_cvrf_updates(encode_source_records(raw), scope=scope)
        )
    )
    require(
        len(records) == 1
        and records[0].claim == claim
        and records[0].source_record_id == revision["source_record_id"],
        "CVRF projection disagrees with retained source",
    )
    return records[0]


def verify_update_rows(cursor, receipt, record, *, row_reader=None):
    from standalone.evidence_pipeline.persistence.attribution import require

    expected = defaultdict(dict)
    mapping = []
    for index, (table, row) in enumerate(record.evidence_rows(receipt["id"])):
        require(row["id"] not in expected[table], "Duplicate CVRF projection")
        expected[table][row["id"]] = row
        mapping.append((index, table, row["id"]))
    if row_reader is None:
        cursor.execute(RECEIPT_ROWS, (receipt["id"],) * (len(TABLES) + 2))
        rows = cursor
    else:
        rows = row_reader.read(receipt["id"])
    stored = defaultdict(dict)
    stored_mapping, batches = [], []
    for kind, payload in rows:
        if kind == "map":
            stored_mapping.append(tuple(payload))
        elif kind == "batch":
            batches.append(payload)
        else:
            require(payload["id"] not in stored[kind], "Duplicate CVRF stored row")
            stored[kind][payload["id"]] = payload
    for table in TABLES:
        require(stored[table] == expected[table], "CVRF projection changed or missing")
    require(sorted(stored_mapping) == mapping, "CVRF projection map changed")
    require(batches == [len(mapping)], "CVRF batch count changed")
    return {table: set(expected[table]) for table in TABLES}


def verify_update_inventory(cursor, sources, revisions, receipts):
    from standalone.evidence_pipeline.persistence.attribution import require

    expected = {
        receipt["id"]
        for receipt in receipts.values()
        if (
            sources[revisions[receipt["source_revision_id"]]["connection_id"]][
                "source_name"
            ],
            sources[revisions[receipt["source_revision_id"]]["connection_id"]][
                "input_kind"
            ],
        )
        == ("MSRC", "security_updates")
    }
    cursor.execute("SELECT to_regclass('evidence_pipeline.cvrf_batches')")
    if cursor.fetchone()[0] is None:
        require(not expected, "Missing CVRF authority")
        return
    cursor.execute("SELECT receipt_id::text FROM evidence_pipeline.cvrf_batches")
    require({row[0] for row in cursor.fetchall()} == expected, "Unexplained CVRF batch")
    cursor.execute(
        "SELECT DISTINCT receipt_id::text FROM evidence_pipeline.cvrf_projection"
    )
    require(
        {row[0] for row in cursor.fetchall()} <= expected,
        "Unexplained CVRF projection map",
    )
