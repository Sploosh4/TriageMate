"""Scheduled Cisco RSS batches; success still requires exact database proof."""

import json

from standalone.evidence_pipeline.parsing.cisco_rss import parse_feed
from standalone.evidence_pipeline.collection.snapshot_bundle import _read


def fixtures(path):
    from .configuration import unique_fields
    from .checkpoint import keys

    document = json.loads(_read(path), object_pairs_hook=unique_fields)
    keys(document, ["origin", "index", "records"])
    if (
        document["origin"] != "synthetic"
        or not isinstance(document["index"], str)
        or not isinstance(document["records"], dict)
        or any(not isinstance(v, str) for v in document["records"].values())
    ):
        raise ValueError("Explicit synthetic Cisco index/record wires required")
    index = document["index"].encode()
    identities = {item.advisory_id for item in parse_feed(index)}
    if set(document["records"]) - identities:
        raise ValueError("Cisco fixture not in exact RSS membership")
    return index, {k: v.encode() for k, v in document["records"].items()}


def collect_batch(
    root,
    *,
    origin,
    execution_id,
    allow_network=False,
    synthetic_index=None,
    synthetic_payloads=None,
    record_limit=10,
    pass_limit=10000,
):
    """Retired collector; original source/tests are preserved in the archive tag."""
    from standalone.evidence_pipeline.collection.collection_scope import (
        require_active_collection,
    )

    require_active_collection("Cisco")
