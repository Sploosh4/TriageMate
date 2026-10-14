"""Bounded scheduled Catalog search, retaining incomplete and failed outcomes."""

import json
from pathlib import Path

from standalone.evidence_pipeline.collection import catalog_collection
from standalone.evidence_pipeline.parsing.catalog_discovery import parse_search
from standalone.evidence_pipeline.collection.snapshot_bundle import (
    _private_directory,
    _read,
)
from standalone.evidence_pipeline.contracts import identifier
from .redhat_worker import BatchResult


def fixtures(path, kb):
    from .configuration import unique_fields

    document = json.loads(_read(path), object_pairs_hook=unique_fields)
    if not isinstance(document, dict) or document.get("origin") != "synthetic":
        raise ValueError("Explicit synthetic Catalog wires required")
    return fixture_data(
        {key: value for key, value in document.items() if key != "origin"}, kb
    )


def fixture_data(document, kb):
    from standalone.evidence_pipeline.parsing.catalog_discovery import combine_pages

    if not isinstance(document, dict) or set(document) not in (
        {"index", "records"},
        {"index", "records", "pages"},
    ):
        raise ValueError("Invalid synthetic Catalog fixture fields")
    if (
        not isinstance(document["index"], str)
        or not isinstance(document["records"], dict)
        or any(not isinstance(value, str) for value in document["records"].values())
    ):
        raise ValueError("Explicit synthetic Catalog wires required")
    raw_pages = document.get("pages", {})
    if not isinstance(raw_pages, dict) or any(
        not isinstance(key, str)
        or not key.isdecimal()
        or str(int(key)) != key
        or not 2 <= int(key) <= 100
        or not isinstance(value, str)
        for key, value in raw_pages.items()
    ):
        raise ValueError("Synthetic Catalog pages require numbered HTML strings")
    pages = {int(key): value.encode() for key, value in raw_pages.items()}
    if sorted(pages) != list(range(2, len(pages) + 2)):
        raise ValueError("Synthetic Catalog page sequence has a gap")
    index = document["index"].encode()
    coverage = combine_pages(
        [parse_search(index, kb=kb)]
        + [parse_search(pages[number], kb=kb) for number in sorted(pages)]
    )
    identities = {hit.update_id for hit in coverage.hits}
    if set(document["records"]) - identities:
        raise ValueError("Synthetic Catalog record is absent from the saved search")
    return (
        index,
        {key: value.encode() for key, value in document["records"].items()},
        pages,
    )


def collect_batch(
    root,
    *,
    origin,
    kb,
    execution_id,
    allow_network=False,
    synthetic_index=None,
    synthetic_payloads=None,
    synthetic_pages=None,
    record_limit=10,
    pass_limit=10,
):
    identifier(execution_id)
    root = Path(root)
    if not root.is_absolute():
        raise ValueError("Catalog bundle root must be absolute")
    _private_directory(root)
    if origin not in {"public", "synthetic"} or type(allow_network) is not bool:
        raise ValueError("Invalid Catalog authority")
    if origin == "synthetic":
        if (
            allow_network
            or not isinstance(synthetic_index, bytes)
            or not isinstance(synthetic_payloads, dict)
        ):
            raise ValueError("Synthetic Catalog workers require offline fixtures")
    elif (
        not allow_network
        or synthetic_index is not None
        or synthetic_payloads is not None
        or synthetic_pages is not None
    ):
        raise ValueError("Public Catalog workers require explicit network opt-in")
    for value, maximum in ((record_limit, 100), (pass_limit, 100)):
        if type(value) is not int or not 1 <= value <= maximum:
            raise ValueError("Invalid Catalog request budget")
    after, examined = None, 0
    for passes in range(1, pass_limit + 1):
        result = catalog_collection.collect(
            root / execution_id,
            origin=origin,
            kb=kb,
            execution_id=execution_id,
            allow_network=allow_network,
            synthetic_index=synthetic_index,
            synthetic_payloads=synthetic_payloads,
            synthetic_pages=synthetic_pages,
            limit=record_limit,
            after=after,
            import_records=True,
        )
        outcomes = result["outcomes"]
        examined += len(outcomes)
        following = result["next_after"]
        if any(
            row.get("outcome") != "success" or row.get("database_imported") is not True
            for row in outcomes
        ):
            reason = "collection_failed"
        elif result["remaining"] == 0 and following is None:
            reason = (
                "finished"
                if result["search_complete"] and result["undiscovered_results"] == 0
                else "incomplete_search"
            )
        elif not outcomes or following is None or following == after:
            reason = "stalled"
        elif passes == pass_limit:
            reason = "budget_exhausted"
        else:
            after = following
            continue
        return BatchResult(reason, passes, examined, following)
