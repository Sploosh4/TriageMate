"""Verify retained public projections against immutable hashed structured claims."""

import hashlib
import json
from datetime import date, datetime
from decimal import Decimal
from collections import defaultdict

from standalone.evidence_pipeline.parsing.devices import stable_id

PUBLIC_PROJECTION_TABLES = frozenset(
    {
        "epss_observations",
        "kev_observations",
        "vulnerability_details",
        "cvss_observations",
        "vulnerability_references",
    }
)


def revision_ordered_receipts(cursor, receipts):
    """Use the existing revision index while retaining the exact allowed set."""
    from standalone.evidence_pipeline.verification_spool import streamed_rows
    from standalone.evidence_pipeline.persistence.attribution import require

    visited = 0
    with streamed_rows(
        cursor,
        "SELECT id::text FROM evidence.observation_receipts ORDER BY source_revision_id",
    ) as rows:
        for (identity,) in rows:
            receipt = receipts.get(identity)
            if receipt is not None:
                visited += 1
                yield receipt
    require(
        visited == len(receipts), "Missing retained receipt during ordered verification"
    )


def verify_public(
    cur, extras, sources, revisions, receipts, explained, verify_receipt, spool
):
    from standalone.evidence_pipeline.persistence.claim_lookup import public_claims
    from standalone.evidence_pipeline.persistence.cvrf_attribution import (
        ReceiptRowsReader,
    )

    with public_claims(cur) as claims, ReceiptRowsReader(cur) as row_reader:
        return _verify_public(
            cur,
            extras,
            sources,
            revisions,
            receipts,
            explained,
            verify_receipt,
            claims,
            spool,
            row_reader,
        )


def _verify_public(
    cur,
    extras,
    sources,
    revisions,
    receipts,
    explained,
    verify_receipt,
    claims,
    spool,
    row_reader,
):
    from standalone.evidence_pipeline.persistence.attribution import require

    from standalone.evidence_pipeline.persistence.cvrf_attribution import (
        verify_update_inventory,
    )
    from standalone.evidence_pipeline.persistence.cve_attribution import (
        verify_cve_receipt,
        verify_cve_inventory,
    )
    from standalone.evidence_pipeline.persistence.osv_attribution import (
        verify_osv_receipt,
        verify_osv_inventory,
    )

    from standalone.evidence_pipeline.persistence.reference_attribution import (
        SOURCES as REFERENCE_SOURCES,
        verify_reference_receipt,
        verify_reference_inventory,
    )

    verify_update_inventory(cur, sources, revisions, receipts)

    public_revisions = spool.reference_mapping(
        revisions,
        "id",
        lambda value: sources[value["connection_id"]]["tenant_id"] is None,
    )
    require(
        set(claims) == set(public_revisions),
        "Unexplained public claim or missing revision",
    )
    allowed = {
        "FIRST": {"epss_observations"},
        "CISA": {"kev_observations", "vulnerability_details"},
        "NVD": {
            "cvss_observations",
            "vulnerability_details",
            "vulnerability_references",
        },
    }
    # Build indexes once rather than scanning every observation for each receipt.
    by_id, by_receipt = {}, {}
    for table in set().union(*allowed.values()):
        # Baseline streams these tables with exact JSON numeric decoding. Reuse
        # those immutable rows rather than re-reading/copying every projection.
        by_id[table] = spool.reference_mapping(extras[table], "id")
        by_receipt[table] = spool.grouped_identities(
            (row["receipt_id"], row["id"]) for row in extras[table]
        )
    legacy_cves = {
        row["cve_id"]
        for row in extras["epss_observations"]
        if row["receipt_id"] not in receipts
    }
    cve_verified = defaultdict(set)
    osv_verified = defaultdict(set)
    reference_verified = set()
    from standalone.evidence_pipeline.persistence.cvrf_attribution import (
        UpdateReconstruction,
    )

    reconstruction = UpdateReconstruction()
    last_revision = None
    for receipt in revision_ordered_receipts(cur, receipts):
        revision = public_revisions.get(receipt["source_revision_id"])
        if revision is None:
            continue
        changed_revision = revision["id"] != last_revision
        if changed_revision:
            # Claims are immutable in this transaction's private spool. Ordered
            # receipts can share one decoded claim, but each receipt identity and
            # its own stored projections still require independent verification.
            claim = claims[revision["id"]]
            content_hash = hashlib.sha256(claim.encode()).hexdigest()
        verify_receipt(
            receipt["id"], revision["source_record_id"], content_hash, "public"
        )
        if changed_revision:
            document = json.loads(claim)
            last_revision = revision["id"]
        source_row = sources[revision["connection_id"]]
        if (source_row["source_name"], source_row["input_kind"]) in REFERENCE_SOURCES:
            verified, cves = verify_reference_receipt(
                cur, source_row, revision, receipt, claim
            )
            reference_verified.update(verified)
            explained["vulnerabilities"].update(cves - legacy_cves)
            continue
        if (source_row["source_name"], source_row["input_kind"]) in {
            ("OSV", "advisories"),
            ("GitHub", "advisories"),
            ("Ubuntu", "advisories"),
        }:
            verified, cves = verify_osv_receipt(
                cur, source_row, revision, receipt, claim
            )
            for table, identities in verified.items():
                osv_verified[table].update(identities)
            explained["vulnerabilities"].update(cves - legacy_cves)
            continue
        if (source_row["source_name"], source_row["input_kind"]) in {
            ("CVE", "records"),
            ("CISA", "vulnrichment"),
        }:
            verified = verify_cve_receipt(cur, source_row, revision, receipt, claim)
            for table, identities in verified.items():
                cve_verified[table].update(identities)
            if revision["source_record_id"] not in legacy_cves:
                explained["vulnerabilities"].add(revision["source_record_id"])
            continue
        native_cvrf = (
            source_row["source_name"] == "MSRC"
            and source_row["input_kind"] == "security_updates"
            and document.get("adapter") == "msrc-cvrf-advisory-v1"
        )
        require(
            document["record"].get("native_id" if native_cvrf else "cve_id")
            == revision["source_record_id"],
            "Public claim identity changed",
        )
        source = sources[revision["connection_id"]]["source_name"]
        if source == "MSRC":
            from standalone.evidence_pipeline.persistence.csaf_attribution import (
                verify_advisory_receipt,
            )

            verifier = verify_advisory_receipt
            if sources[revision["connection_id"]]["input_kind"] == "security_updates":
                from standalone.evidence_pipeline.persistence.cvrf_attribution import (
                    verify_update_receipt,
                )

                verifier = verify_update_receipt
            options = (
                {"reconstruction": reconstruction, "row_reader": row_reader}
                if source_row["input_kind"] == "security_updates"
                else {}
            )
            verified = verifier(cur, source_row, revision, receipt, claim, **options)
            for table, identities in verified.items():
                explained[table].update(identities)
            if not native_cvrf and revision["source_record_id"] not in legacy_cves:
                explained["vulnerabilities"].add(revision["source_record_id"])
            continue
        expected_ids = set()
        for index, (table, fields) in enumerate(document["projection"]):
            require(table in allowed[source], "Unexpected public projection table")
            expected = dict(fields)
            for key, value in expected.items():
                if isinstance(value, dict) and set(value) == {"decimal"}:
                    expected[key] = Decimal(value["decimal"])
                elif isinstance(value, dict) and set(value) == {"iso"}:
                    text = value["iso"]
                    expected[key] = (
                        datetime.fromisoformat(text)
                        if "T" in text
                        else date.fromisoformat(text)
                    )
            identity = stable_id("public-observation", receipt["id"], table, str(index))
            expected.update(
                id=identity,
                cve_id=revision["source_record_id"],
                receipt_id=receipt["id"],
            )
            require(identity in by_id[table], "Missing public projection")
            actual = by_id[table][identity]
            # baseline reads date/numeric values through JSON; compare its canonical types.
            for key, value in expected.items():
                if isinstance(value, datetime) and isinstance(actual.get(key), str):
                    actual[key] = datetime.fromisoformat(actual[key])
                elif isinstance(value, date) and isinstance(actual.get(key), str):
                    actual[key] = date.fromisoformat(actual[key])
            require(
                all(actual.get(k) == v for k, v in expected.items())
                and all(v is None for k, v in actual.items() if k not in expected),
                "Public projection changed",
            )
            explained[table].add(identity)
            expected_ids.add(identity)
        for table in allowed[source]:
            require(
                by_receipt[table].get(receipt["id"], set()) <= expected_ids,
                "Unexplained public observation",
            )
        # Leave CVE catalogue rows used by the separate retained EPSS importer to its verifier.
        if revision["source_record_id"] not in legacy_cves:
            explained["vulnerabilities"].add(revision["source_record_id"])
    verify_cve_inventory(cur, cve_verified)
    verify_osv_inventory(cur, osv_verified)
    verify_reference_inventory(cur, reference_verified)
