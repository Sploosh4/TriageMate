"""Collect the exact current RSS membership in bounded, replayable batches."""

from standalone.evidence_pipeline.contracts import SourceScope
from standalone.evidence_pipeline.parsing.devices import stable_id

PROVENANCE = (
    "Cisco public Security Advisory; original document notices retained; "
    "https://sec.cloudapps.cisco.com/security/center/resources/security_vulnerability_policy.html; "
    "selected local document, not an aggregator mirror"
)


def source_scope(origin, item):
    return SourceScope(
        stable_id("cisco-rss-advisory", origin, item.url),
        "Cisco",
        "advisories",
        item.url,
        origin,
        PROVENANCE
        if origin == "public"
        else "TriageMate generated synthetic Cisco RSS/advisory fixtures",
    )


def collect(
    root,
    *,
    origin,
    execution_id,
    limit=10,
    after=None,
    synthetic_index=None,
    synthetic_payloads=None,
    allow_network=False,
    replay_only=False,
    import_records=False,
):
    """Retired collector; original source/tests are preserved in the archive tag."""
    from standalone.evidence_pipeline.collection.collection_scope import (
        require_active_collection,
    )

    require_active_collection("Cisco")
