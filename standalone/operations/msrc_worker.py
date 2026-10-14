"""MSRC publication batch worker; success still requires exact database proof."""

from pathlib import Path
import json

from standalone.evidence_pipeline.collection import msrc_discovered_collection
from standalone.evidence_pipeline.parsing.msrc_publications import publications
from standalone.evidence_pipeline.collection.msrc_publication_selection import (
    select_changed,
)
from io import BytesIO
from standalone.evidence_pipeline.contracts import identifier
from standalone.evidence_pipeline.collection.snapshot_bundle import (
    _private_directory,
    _read,
)
from .redhat_worker import BatchResult


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
        raise ValueError("Explicit synthetic MSRC index/record wires required")
    index = document["index"].encode()
    identities = {item.publication_id for item in publications(BytesIO(index))}
    if set(document["records"]) - identities:
        raise ValueError("MSRC fixture not in exact publication-index membership")
    return index, {k: v.encode() for k, v in document["records"].items()}


def collect_batch(
    root,
    *,
    origin,
    execution_id,
    starting_month,
    retained_ids,
    allow_network=False,
    synthetic_index=None,
    synthetic_payloads=None,
    record_limit=10,
    pass_limit=10000,
):
    identifier(execution_id)
    list(
        select_changed((), (), starting_month=starting_month, retained_ids=retained_ids)
    )
    root = Path(root)
    if not root.is_absolute():
        raise ValueError("MSRC bundle root must be absolute")
    _private_directory(root)
    if origin not in {"public", "synthetic"} or type(allow_network) is not bool:
        raise ValueError("Invalid MSRC worker authority")
    if origin == "synthetic":
        if (
            allow_network
            or not isinstance(synthetic_index, bytes)
            or not isinstance(synthetic_payloads, dict)
        ):
            raise ValueError("Synthetic MSRC worker requires offline fixtures")
    elif (
        not allow_network
        or synthetic_index is not None
        or synthetic_payloads is not None
    ):
        raise ValueError("Public MSRC worker requires explicit network opt-in")
    for value, maximum in ((record_limit, 100), (pass_limit, 10000)):
        if type(value) is not int or not 1 <= value <= maximum:
            raise ValueError("Invalid MSRC worker request budget")
    after = None
    examined = 0
    for passes in range(1, pass_limit + 1):
        result = msrc_discovered_collection.collect(
            root / execution_id,
            origin=origin,
            execution_id=execution_id,
            starting_month=starting_month,
            retained_ids=retained_ids,
            allow_network=allow_network,
            synthetic_index=synthetic_index,
            synthetic_payloads=synthetic_payloads,
            limit=record_limit,
            after=after,
            import_records=True,
        )
        outcomes = result["outcomes"]
        examined += len(outcomes)
        following = result["next_after"]
        if not result["index_complete"] or any(
            row.get("outcome") != "success" or row.get("database_imported") is not True
            for row in outcomes
        ):
            reason = "collection_failed"
        elif result["remaining"] == 0 and following is None:
            reason = "finished"
        elif not outcomes or following is None or following == after:
            reason = "stalled"
        elif passes == pass_limit:
            reason = "budget_exhausted"
        else:
            after = following
            continue
        return BatchResult(reason, passes, examined, following)
