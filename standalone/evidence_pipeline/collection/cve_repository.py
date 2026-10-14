"""Collect CVE/CISA repository records in bounded, replayable bucket passes."""

from dataclasses import dataclass
import re
from pathlib import Path

from standalone.evidence_pipeline.contracts import identifier
from standalone.evidence_pipeline.parsing.cve_discovery import REPOSITORIES, PARTITION
from standalone.evidence_pipeline.parsing.ubuntu_discovery import (
    PARTITION as UBUNTU_PARTITION,
)
from standalone.evidence_pipeline.collection.github_scan import scan, scan_current
from standalone.evidence_pipeline.collection.github_dispatch import dispatch


@dataclass(frozen=True)
class RepositoryPass:
    commit: str | None
    metadata_collected: int
    outcomes: tuple[dict, ...]
    next_partition: str | None
    next_after: str | None
    pending_metadata: tuple[tuple[str, str], ...]
    metadata_failures: tuple[tuple[str, str], ...]
    enumeration_finished: bool
    collection_complete: bool | None = None
    database_complete: bool | None = None
    snapshot_published: bool | None = None


def collect(
    source,
    bundle,
    *,
    origin,
    execution_id,
    metadata_limit=10,
    record_limit=10,
    next_partition=None,
    after=None,
    synthetic_objects=None,
    synthetic_payloads=None,
    allow_network=False,
    replay_only=False,
    import_records=False,
):
    """Pin the branch once, then resume through its discovered year/buckets.

    Enumeration completion does not establish successful collection/import. Every
    record outcome remains separate; failed bundles are retained without retries.
    The caller must retain outcomes across passes before declaring full coverage.
    """
    from standalone.evidence_pipeline.collection.collection_scope import (
        require_active_collection,
    )

    require_active_collection(source)
    identifier(execution_id)
    if (
        source not in {*REPOSITORIES, "Ubuntu", "WA SOC"}
        or type(metadata_limit) is not int
        or not 0 <= metadata_limit <= 100
        or type(record_limit) is not int
        or not 1 <= record_limit <= 100
    ):
        raise ValueError("Invalid CVE repository source or pass budget")
    if any(
        type(flag) is not bool for flag in (allow_network, replay_only, import_records)
    ) or (allow_network and (origin != "public" or replay_only)):
        raise ValueError("Invalid CVE repository collection mode")
    if next_partition is not None and (
        not isinstance(next_partition, str)
        or not (
            re.compile("advisories")
            if source == "WA SOC"
            else UBUNTU_PARTITION
            if source == "Ubuntu"
            else PARTITION
        ).fullmatch(next_partition)
    ):
        raise ValueError("Invalid CVE continuation partition")
    if after is not None and next_partition is None:
        raise ValueError("CVE file continuation requires a partition")
    if synthetic_payloads is not None and (
        origin != "synthetic" or not isinstance(synthetic_payloads, dict)
    ):
        raise ValueError("Synthetic CVE records require synthetic origin")
    bundle = Path(bundle)
    cache = bundle / "objects"
    options = dict(
        source=source,
        origin=origin,
        synthetic_objects=synthetic_objects,
        allow_network=allow_network,
        replay_only=replay_only,
        object_cache=cache,
    )
    index = scan_current(bundle, limit=metadata_limit, **options)
    used = index.collected_objects
    commit = index.discovery.commit if index.discovery else None
    if not index.complete:
        return RepositoryPass(
            commit,
            used,
            (),
            next_partition,
            after,
            index.pending_objects,
            index.failures,
            False,
        )
    partitions = index.discovery.partitions
    if next_partition is not None and next_partition not in partitions:
        raise ValueError("CVE continuation does not belong to the pinned repository")
    start = partitions.index(next_partition) if next_partition else 0
    outcomes = []
    for position in range(start, len(partitions)):
        partition = partitions[position]
        file_after = after if position == start else None
        available = record_limit - len(outcomes)
        if not available:
            return RepositoryPass(
                commit, used, tuple(outcomes), partition, file_after, (), (), False
            )
        path = bundle / ("partition-" + partition.replace("/", "-"))
        part = scan(
            commit, path, limit=metadata_limit - used, partition=partition, **options
        )
        used += part.collected_objects
        if not part.complete:
            return RepositoryPass(
                commit,
                used,
                tuple(outcomes),
                partition,
                file_after,
                part.pending_objects,
                part.failures,
                False,
            )
        batch = dispatch(
            commit,
            path,
            bundle / "records",
            source=source,
            origin=origin,
            execution_id=execution_id,
            partition=partition,
            limit=available,
            after=file_after,
            synthetic_payloads=synthetic_payloads,
            allow_network=allow_network,
            replay_only=replay_only,
            import_records=import_records,
            object_cache=cache,
        )
        outcomes.extend(batch.outcomes)
        if batch.remaining:
            return RepositoryPass(
                commit,
                used,
                tuple(outcomes),
                partition,
                batch.next_after,
                (),
                (),
                False,
            )
    from standalone.evidence_pipeline.collection.github_completion import inspect_run

    publication = None
    if import_records:
        from contextlib import closing
        from standalone.evidence_pipeline.runtime import connect
        from standalone.evidence_pipeline.persistence.cve_current import publish

        with closing(connect()) as conn, conn, conn.cursor() as cursor:
            publication = publish(
                cursor, source, bundle, origin=origin, execution_id=execution_id
            )
            completion = dict(
                collection_complete=publication.collection_complete,
                database_complete=publication.database_complete,
            )
    else:
        completion = inspect_run(
            commit, bundle, source=source, origin=origin, execution_id=execution_id
        )
    return RepositoryPass(
        commit,
        used,
        tuple(outcomes),
        None,
        None,
        (),
        (),
        True,
        completion["collection_complete"],
        completion["database_complete"],
        publication.published if publication is not None else None,
    )


def main(argv=None):
    import argparse
    from dataclasses import asdict
    import json
    import sys

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source", choices=("CVE", "CISA", "Ubuntu", "WA SOC"), required=True
    )
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--origin", choices=("public", "synthetic"), required=True)
    parser.add_argument("--execution-id", required=True)
    parser.add_argument("--metadata-limit", type=int, default=10)
    parser.add_argument("--record-limit", type=int, default=10)
    parser.add_argument("--next-partition")
    parser.add_argument("--after")
    parser.add_argument("--import", dest="import_records", action="store_true")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--allow-network", action="store_true")
    mode.add_argument("--replay-only", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = collect(**vars(args))
        print(json.dumps(asdict(result), sort_keys=True))
        # Enumeration alone does not prove successful or imported repository data.
        return (
            0
            if result.collection_complete
            and (not args.import_records or result.database_complete)
            else 2
        )
    except (ValueError, OSError, TypeError, KeyError) as exc:
        print(f"CVE repository collection failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
