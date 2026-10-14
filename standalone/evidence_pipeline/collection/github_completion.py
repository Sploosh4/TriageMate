"""Reconstruct repository completion from saved evidence, not the last pass alone."""

from pathlib import Path
import os

from standalone.evidence_pipeline.contracts import identifier
from standalone.evidence_pipeline.parsing.devices import stable_id
from standalone.evidence_pipeline.collection.github_dispatch import (
    source_scope,
    record_options,
)
from standalone.evidence_pipeline.collection.github_scan import scan
from standalone.evidence_pipeline.collection.public_collection import prepare


def inspect_run(commit, bundle, *, origin, execution_id, cursor=None, source="GitHub"):
    """Read all pinned metadata and advisory bundles without network or writes.

    With a cursor, verify each successful bundle has its matching committed native
    advisory receipt. Without one, database completion is explicitly unverified.
    Missing/incomplete metadata raises; callers must not publish a current snapshot.
    """
    execution_id = identifier(execution_id)
    bundle = Path(bundle)
    cache = bundle / "objects"

    def metadata(path, **options):
        result = scan(
            commit,
            path,
            origin=origin,
            replay_only=True,
            object_cache=cache,
            source=source,
            **options,
        )
        if not result.complete:
            raise ValueError("Repository completion requires all pinned metadata")
        return result.discovery

    index = (
        metadata(bundle, index_only=True)
        if source == "GitHub"
        else metadata(bundle / "scan")
    )
    advisory_root = bundle / ("advisories" if source == "GitHub" else "records")
    if advisory_root.is_symlink() or (
        advisory_root.exists()
        and (
            not advisory_root.is_dir()
            or advisory_root.stat().st_mode & 0o077
            or advisory_root.stat().st_uid != os.getuid()
        )
    ):
        raise ValueError(
            "Repository completion requires an owner-only advisory directory"
        )
    outcomes, expected = [], {}
    for month in index.partitions:
        chunks = (month,)
        if source == "GitHub":
            monthly = metadata(
                bundle / ("index-" + month.replace("/", "-")),
                partition=month,
                index_only=True,
            )
            chunks = monthly.partitions
        for chunk in chunks:
            discovered = metadata(
                bundle / ("partition-" + chunk.replace("/", "-")), partition=chunk
            )
            for file in discovered.files:
                scope = source_scope(file, origin)
                attempt = stable_id(
                    "github-discovered-attempt", execution_id, scope.connection_id
                )
                path = advisory_root / attempt
                row = dict(
                    path=file.path,
                    execution_id=attempt,
                    connection_id=scope.connection_id,
                    outcome="pending",
                    receipt_id=None,
                    database_imported=None if cursor is None else False,
                )
                if path.exists() or path.is_symlink():
                    try:
                        saved = prepare(
                            scope,
                            attempt,
                            path,
                            **(
                                {}
                                if source == "WA SOC"
                                else dict(
                                    repository_commit=commit, repository_path=file.path
                                )
                            ),
                            replay_only=True,
                            **record_options(file, source),
                        )
                        row["outcome"] = (
                            saved.error_code if not saved.complete else "success"
                        )
                        if saved.complete:
                            file.verify_payload(saved.payload)
                            expected[attempt] = (
                                scope.connection_id,
                                saved.input_fingerprint,
                                file.advisory_id
                                if source == "WA SOC"
                                else file.path.rsplit("/", 1)[1].removesuffix(".json"),
                            )
                    except (ValueError, OSError):
                        row["outcome"] = "invalid_advisory_bundle"
                outcomes.append(row)
    if cursor is not None:
        imported = {}
        attempts = list(expected)
        observation = (
            "evidence.public_reference_observations"
            if source == "WA SOC"
            else (
                "evidence.osv_advisory_observations"
                if source in {"GitHub", "Ubuntu"}
                else "evidence.cve_record_observations"
            )
        )
        native_column = (
            "o.native_id"
            if source == "WA SOC"
            else ("o.advisory_id" if source in {"GitHub", "Ubuntu"} else "o.cve_id")
        )
        for start in range(0, len(attempts), 128):
            cursor.execute(
                "SELECT a.id::text,a.connection_id::text,a.input_fingerprint,"
                + native_column
                + ",o.receipt_id::text "
                "FROM evidence.collection_attempts a "
                "JOIN evidence.observation_receipts r ON r.collection_attempt_id=a.id "
                "JOIN " + observation + " o ON o.receipt_id=r.id "
                "WHERE a.id=ANY(%s::uuid[]) AND a.complete AND a.outcome='success'",
                (attempts[start : start + 128],),
            )
            for attempt, connection, fingerprint, native, receipt in cursor.fetchall():
                if (
                    expected[attempt] != (connection, fingerprint, native)
                    or attempt in imported
                ):
                    raise ValueError(
                        "Repository import differs from its saved native advisory"
                    )
                imported[attempt] = receipt
        for row in outcomes:
            receipt = imported.get(row["execution_id"])
            row.update(receipt_id=receipt, database_imported=receipt is not None)
    return dict(
        commit=commit,
        origin=origin,
        execution_id=execution_id,
        outcomes=outcomes,
        collection_complete=all(row["outcome"] == "success" for row in outcomes),
        database_complete=all(row["database_imported"] for row in outcomes)
        if cursor is not None
        else None,
    )
