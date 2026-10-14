"""Bounded Red Hat index execution; completion still needs independent DB proof."""

from dataclasses import dataclass


def fixtures(path):
    """Load one bounded owner-only file containing explicitly synthetic wire bytes."""
    import json
    from .configuration import unique_fields
    from .checkpoint import keys
    from standalone.evidence_pipeline.collection.snapshot_bundle import _read
    from standalone.evidence_pipeline.parsing.redhat_discovery import parse_index

    document = json.loads(_read(path), object_pairs_hook=unique_fields)
    keys(document, ["origin", "index", "records"])
    if (
        document["origin"] != "synthetic"
        or not isinstance(document["index"], str)
        or not isinstance(document["records"], dict)
        or any(not isinstance(value, str) for value in document["records"].values())
    ):
        raise ValueError("Explicit synthetic Red Hat index and record wires required")
    index = document["index"].encode()
    paths = {entry.path for entry in parse_index(index)}
    if set(document["records"]) - paths:
        raise ValueError("Synthetic records must belong to the exact index")
    return index, {key: value.encode() for key, value in document["records"].items()}


@dataclass(frozen=True)
class BatchResult:
    reason: str
    passes: int
    records_examined: int
    next_after: str | None


def collect_batch(
    bundle_root,
    *,
    origin,
    execution_id,
    allow_network=False,
    synthetic_index=None,
    synthetic_payloads=None,
    record_limit=100,
    pass_limit=10000,
):
    """Retired collector; original source/tests are preserved in the archive tag."""
    from standalone.evidence_pipeline.collection.collection_scope import (
        require_active_collection,
    )

    require_active_collection("Red Hat")
