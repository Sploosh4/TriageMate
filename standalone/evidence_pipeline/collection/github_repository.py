"""Run bounded metadata and advisory passes across a pinned repository's months."""

from dataclasses import dataclass


@dataclass(frozen=True)
class RepositoryPass:
    metadata_collected: int
    advisory_outcomes: tuple[dict, ...]
    next_partition: str | None
    next_after: str | None
    pending_metadata: tuple[tuple[str, str], ...]
    metadata_failures: tuple[tuple[str, str], ...]
    enumeration_finished: bool
    collection_complete: bool | None = None
    database_complete: bool | None = None


def collect(
    commit,
    bundle,
    *,
    origin,
    execution_id,
    metadata_limit=10,
    advisory_limit=10,
    next_partition=None,
    after=None,
    synthetic_objects=None,
    synthetic_payloads=None,
    allow_network=False,
    replay_only=False,
    import_records=False,
):
    """Retired collector; original source/tests are preserved in the archive tag."""
    from standalone.evidence_pipeline.collection.collection_scope import (
        require_active_collection,
    )

    require_active_collection("GitHub")


def collect_current(
    bundle,
    *,
    origin,
    execution_id,
    metadata_limit=10,
    advisory_limit=10,
    next_partition=None,
    after=None,
    synthetic_objects=None,
    synthetic_payloads=None,
    allow_network=False,
    replay_only=False,
    import_records=False,
):
    """Retired collector; original source/tests are preserved in the archive tag."""
    from standalone.evidence_pipeline.collection.collection_scope import (
        require_active_collection,
    )

    require_active_collection("GitHub")
