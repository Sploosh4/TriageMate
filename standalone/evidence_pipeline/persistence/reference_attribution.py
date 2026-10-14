"""Rebuild reference projections from retained publisher fields."""

import csv
import hashlib
import io
import json
from decimal import Decimal

from standalone.evidence_pipeline.contracts import SourceScope
from standalone.evidence_pipeline.parsing.devices import stable_id
from standalone.evidence_pipeline.parsing.reference_records import normalize_references
from standalone.evidence_pipeline.parsing import (
    attack_definitions,
    ctid_mappings,
    exploit_db,
)
from standalone.evidence_pipeline.parsing.cve_records import source_json

from standalone.evidence_pipeline.parsing.redhat_advisories import parse_redhat
from standalone.evidence_pipeline.parsing import advisory_feeds

SOURCES = {
    **dict.fromkeys(advisory_feeds.SOURCES, advisory_feeds.parse_advisory),
    ("Red Hat", "advisories"): parse_redhat,
    ("Exploit-DB", "metadata"): exploit_db.parse_exploit_db,
    ("CTID", "cve_mappings"): ctid_mappings.parse_ctid,
    ("MITRE ATT&CK", "enterprise_definitions"): attack_definitions.parse_attack,
}
TABLE = "public_reference_observations"


def reconstruct_reference(scope, claim):
    document = json.loads(claim)
    if document.get("adapter") != "public-reference-v1":
        raise ValueError("Unknown public reference adapter")
    fields = json.loads(document["source_fields"], parse_float=Decimal)
    if (scope.source, scope.input_kind) in advisory_feeds.SOURCES:
        payload = advisory_feeds.reconstruct_payload(fields)
    elif scope.source == "Red Hat":
        payload = source_json(fields["document"]).encode()
    elif scope.source == "MITRE ATT&CK":
        bundle = dict(fields["collection_metadata"])
        collections = bundle.pop("collections")
        bundle["objects"] = [fields["object"], *collections]
        payload = source_json(bundle).encode()
    else:
        rows = fields["raw_rows"]
        if not rows:
            raise ValueError("Missing reference source rows")
        output = io.StringIO(newline="")
        writer = csv.DictWriter(output, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
        payload = output.getvalue().encode()
    parser = SOURCES[(scope.source, scope.input_kind)]
    records = list(normalize_references(parser(payload, scope=scope)))
    if len(records) != 1 or records[0].claim != claim:
        raise ValueError("Reference projection disagrees with retained source")
    return records[0]


def verify_reference_inventory(cursor, verified):
    from standalone.evidence_pipeline.persistence.attribution import require

    cursor.execute("SELECT to_regclass(%s)", ("evidence." + TABLE,))
    if cursor.fetchone()[0] is None:
        require(not verified, "Missing reference evidence table")
        return
    cursor.execute("SELECT id::text FROM evidence.public_reference_observations")
    require(
        {row[0] for row in cursor.fetchall()} == verified,
        "Unexplained public reference evidence",
    )


def verify_reference_receipt(cursor, source, revision, receipt, claim):
    from standalone.evidence_pipeline.persistence.attribution import require

    require(
        (source["source_name"], source["input_kind"]) in SOURCES
        and source["tenant_id"] is None,
        "Invalid public reference source",
    )
    digest = hashlib.sha256(claim.encode()).hexdigest()
    require(
        revision["connection_id"] == source["id"]
        and revision["content_hash"] == digest
        and revision["source_url"] == source["scope_reference"]
        and revision["id"]
        == stable_id(
            "public-revision", source["id"], revision["source_record_id"], digest
        )
        and receipt["source_revision_id"] == revision["id"]
        and receipt["id"]
        == stable_id(
            "public-receipt", revision["id"], receipt["collection_attempt_id"]
        ),
        "Reference claim or receipt identity changed",
    )
    scope = SourceScope(
        source["id"],
        source["source_name"],
        source["input_kind"],
        source["scope_reference"],
        revision["origin"],
        revision["licence_or_provenance"],
    )
    record = reconstruct_reference(scope, claim)
    require(
        record.source_record_id == revision["source_record_id"],
        "Reference native identity changed",
    )
    _, expected = next(record.evidence_rows(receipt["id"]))
    expected["source_fields"] = json.loads(
        expected["source_fields"], parse_float=Decimal
    )
    cursor.execute(
        "SELECT to_jsonb(t)::text FROM evidence.public_reference_observations t WHERE receipt_id=%s",
        (receipt["id"],),
    )
    stored = [json.loads(text, parse_float=Decimal) for (text,) in cursor.fetchall()]
    require(stored == [expected], "Reference projection changed or missing")
    return {expected["id"]}, set(record.cve_ids)
