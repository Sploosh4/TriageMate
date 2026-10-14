"""Bounded repository execution; scheduler acceptance still requires DB proof."""

from dataclasses import dataclass
from pathlib import Path

from standalone.evidence_pipeline.collection import cve_repository, github_repository
from standalone.evidence_pipeline.contracts import identifier
from standalone.evidence_pipeline.collection.snapshot_bundle import _private_directory


@dataclass(frozen=True)
class BatchResult:
    reason: str
    passes: int
    metadata_collected: int
    records_examined: int
    next_partition: str | None
    next_after: str | None


def collect_batch(
    source,
    bundle_root,
    *,
    origin,
    execution_id,
    allow_network=False,
    synthetic_objects=None,
    synthetic_payloads=None,
    metadata_limit=10,
    record_limit=100,
    pass_limit=10000,
):
    """Advance successful passes without retrying failed saved collections.

    The run owns a UUID subdirectory. Re-entering the same run reconstructs its
    progress from immutable bundles; it cannot resolve a new repository head.
    Budgets bound this invocation, including replayed records. A finished result
    is a worker observation, never the supervisor's committed-success proof.
    """
    from standalone.evidence_pipeline.collection.collection_scope import (
        require_active_collection,
    )

    require_active_collection(source)
    identifier(execution_id)
    if source not in {"GitHub", "CVE", "CISA", "Ubuntu", "WA SOC"}:
        raise ValueError("Unsupported scheduled repository")
    for value, maximum in (
        (metadata_limit, 100),
        (record_limit, 100),
        (pass_limit, 10000),
    ):
        if type(value) is not int or not 1 <= value <= maximum:
            raise ValueError("Invalid scheduled repository budget")
    if type(allow_network) is not bool or origin not in {"synthetic", "public"}:
        raise ValueError("Invalid scheduled repository authority")
    if origin == "synthetic":
        if (
            allow_network
            or not isinstance(synthetic_objects, dict)
            or not isinstance(synthetic_payloads, dict)
        ):
            raise ValueError("Synthetic repository requires offline fixtures")
    elif (
        not allow_network
        or synthetic_objects is not None
        or synthetic_payloads is not None
    ):
        raise ValueError("Public repository requires explicit network authority")
    root = Path(bundle_root)
    if not root.is_absolute():
        raise ValueError("Repository bundle root must be absolute")
    _private_directory(root)
    bundle = root / execution_id
    partition = after = None
    metadata = records = 0
    for passes in range(1, pass_limit + 1):
        options = dict(
            origin=origin,
            execution_id=execution_id,
            metadata_limit=metadata_limit,
            next_partition=partition,
            after=after,
            synthetic_objects=synthetic_objects,
            synthetic_payloads=synthetic_payloads,
            allow_network=allow_network,
            import_records=True,
        )
        if source == "GitHub":
            result = github_repository.collect_current(
                bundle, advisory_limit=record_limit, **options
            )
            outcomes = result.advisory_outcomes
        else:
            result = cve_repository.collect(
                source, bundle, record_limit=record_limit, **options
            )
            outcomes = result.outcomes
        metadata += result.metadata_collected
        records += len(outcomes)
        next_cursor = result.next_partition, result.next_after
        reason = None
        if result.metadata_failures or any(
            row.get("outcome") != "success" or row.get("database_imported") is not True
            for row in outcomes
        ):
            reason = "collection_failed"
        elif result.enumeration_finished:
            reason = (
                "finished"
                if result.collection_complete is True
                and result.database_complete is True
                and (source == "GitHub" or result.snapshot_published is True)
                else "incomplete_evidence"
            )
        elif (
            not result.metadata_collected
            and not outcomes
            and next_cursor == (partition, after)
        ):
            reason = "stalled"
        elif passes == pass_limit:
            reason = "budget_exhausted"
        if reason is not None:
            return BatchResult(reason, passes, metadata, records, *next_cursor)
        partition, after = next_cursor
