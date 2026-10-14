"""Generated Cisco records prove identity binding and inactive-source boundaries."""

from dataclasses import replace
import json
from uuid import uuid4
import pytest

from standalone.evidence_pipeline.parsing.cisco_advisories import parse_cisco
from standalone.evidence_pipeline.parsing.cisco_discovery import BASE
from standalone.evidence_pipeline.parsing.csaf import parse_csaf
from .test_csaf import fixture, scope


def example():
    chosen = replace(
        scope(),
        source="Cisco",
        scope_reference=BASE + "2099/cisco-sa-synthetic-abc.json",
    )
    raw = fixture()
    raw["document"]["tracking"]["id"] = "cisco-sa-synthetic-AbC"
    raw["document"]["publisher"] = {"name": "Synthetic Cisco fixture"}
    raw["document"]["notes"] = [
        {
            "category": "general",
            "title": "Fixed Software",
            "text": "Synthetic prose only",
        }
    ]
    return chosen, raw


def test_native_identity_complete_document_and_source_claims_survive():
    chosen, raw = example()
    feed = parse_cisco(json.dumps(raw).encode(), scope=chosen)
    assert feed.advisory_id == "cisco-sa-synthetic-AbC"
    assert json.loads(feed.raw_payload) == raw
    assert feed.records[0].product_status == (("known_affected", ("p1",)),)
    assert feed.records[0].remediations[0].patch_id is None
    assert not hasattr(feed.records[0].remediations[0], "fixed_version")
    raw["vulnerabilities"] = []
    assert parse_cisco(json.dumps(raw).encode(), scope=chosen).records == ()


@pytest.mark.parametrize(
    "change", ["public", "tenant", "path", "identity", "relationship"]
)
def test_unsafe_scope_and_mismatched_claims_are_rejected(change):
    chosen, raw = example()
    if change == "public":
        chosen = replace(chosen, origin="public")
        with pytest.raises(ValueError):
            parse_csaf(json.dumps(raw).encode(), scope=chosen)
    elif change == "tenant":
        chosen = replace(chosen, tenant_id=str(uuid4()))
    elif change == "path":
        chosen = replace(chosen, scope_reference=chosen.scope_reference + "?redirect=1")
    elif change == "identity":
        raw["document"]["tracking"]["id"] = "cisco-sa-different-AbC"
    else:
        raw["product_tree"]["relationships"] = [
            dict(
                category="default_component_of",
                product_reference="missing",
                relates_to_product_reference="p1",
                full_product_name=dict(product_id="pair", name="Synthetic pair"),
            )
        ]
    with pytest.raises(ValueError):
        parse_cisco(json.dumps(raw).encode(), scope=chosen)


@pytest.mark.parametrize("origin", ["synthetic", "public"])
def test_publisher_document_route_binds_exact_mixed_case_identity(origin):
    from standalone.evidence_pipeline.parsing.cisco_rss import endpoint

    chosen, raw = example()
    native = raw["document"]["tracking"]["id"]
    chosen = replace(chosen, origin=origin, scope_reference=endpoint(native))
    feed = parse_cisco(json.dumps(raw).encode(), scope=chosen)
    assert feed.advisory_id == native
    assert json.loads(feed.raw_payload) == raw
    raw["document"]["tracking"]["id"] = native.lower()
    with pytest.raises(ValueError, match="identity differs"):
        parse_cisco(json.dumps(raw).encode(), scope=chosen)


def test_rss_route_normalizes_and_reconstructs_with_publisher_clock():
    from datetime import datetime, timezone
    from standalone.operations.provider_age import provider_clock
    from standalone.evidence_pipeline.parsing.cisco_rss import endpoint
    from standalone.evidence_pipeline.parsing.advisory_feeds import parse_advisory
    from standalone.evidence_pipeline.parsing.public_records import normalize_public
    from standalone.evidence_pipeline.persistence.reference_attribution import (
        reconstruct_reference,
    )

    chosen, raw = example()
    chosen = replace(
        chosen, scope_reference=endpoint(raw["document"]["tracking"]["id"])
    )
    feed = parse_advisory(json.dumps(raw).encode(), scope=chosen)
    (record,) = normalize_public(feed)
    assert reconstruct_reference(chosen, record.claim) == record
    assert provider_clock(feed) == (
        datetime(2026, 1, 2, tzinfo=timezone.utc),
        "record_last_modified",
        "timestamp",
    )
