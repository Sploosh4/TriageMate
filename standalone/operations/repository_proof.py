"""Read-only proof that a repository run published its exact saved membership."""

from pathlib import Path
from dataclasses import dataclass
import re

from psycopg2 import sql

from standalone.evidence_pipeline.parsing import (
    cve_discovery,
    github_discovery,
    ubuntu_discovery,
)
from standalone.evidence_pipeline.contracts import identifier
from standalone.evidence_pipeline.collection.github_completion import inspect_run
from standalone.evidence_pipeline.collection.github_discovery_collection import prepare
from .repository_recipe import SOURCE_URLS


@dataclass(frozen=True)
class ScheduledRepository:
    input_id: str
    worker_contract: str
    source: str
    origin: str
    bundle_root: Path
    kb: str | None = None
    starting_month: str | None = None
    retained_ids: frozenset[str] = frozenset()

    def __post_init__(self):
        if self.source == "MSRC":
            from .msrc_proof import MsrcProof

            MsrcProof(self.starting_month, self.retained_ids)
        elif self.starting_month is not None or self.retained_ids:
            raise ValueError("Publication proof range requires MSRC")
        if self.source == "Microsoft Update Catalog":
            from standalone.evidence_pipeline.parsing.catalog_discovery import (
                search_url,
            )

            search_url(self.kb)
        elif self.kb is not None:
            raise ValueError("KB proof binding requires Catalog")
        if self.input_id != identifier(self.input_id):
            raise ValueError("Repository input identity must be canonical")
        if (
            not isinstance(self.worker_contract, str)
            or re.fullmatch(r"[a-f0-9]{64}", self.worker_contract) is None
            or self.source not in SOURCE_URLS
            or self.origin not in {"synthetic", "public"}
            or not isinstance(self.bundle_root, Path)
            or not self.bundle_root.is_absolute()
        ):
            raise ValueError("Invalid scheduled repository proof binding")

    def committed(self, cursor, key, job):
        from .store import load

        if job.input_id != self.input_id or job.prerequisite_snapshots:
            return False
        saved = load(cursor, key)
        if saved is None:
            return False
        state = saved[1]
        definition = state.definitions.get(self.input_id)
        active = state.inputs.get(self.input_id)
        if (
            definition is None
            or definition.worker_contract != self.worker_contract
            or active is None
            or active.active != job
            or job.run_id not in state.control.active
        ):
            return False
        if self.source == "MSRC":
            from .msrc_proof import MsrcProof

            return MsrcProof(self.starting_month, self.retained_ids).committed(
                cursor, key, job, self.origin, self.bundle_root, self.worker_contract
            )
        if self.source == "Cisco":
            from .cisco_proof import CiscoProof

            return CiscoProof().committed(
                cursor, key, job, self.origin, self.bundle_root, self.worker_contract
            )
        if self.source == "Microsoft Update Catalog":
            from .catalog_proof import CatalogProof

            return CatalogProof(self.kb).committed(
                cursor, key, job, self.origin, self.bundle_root, self.worker_contract
            )
        if self.source == "Red Hat":
            from .redhat_proof import committed

            return committed(
                cursor, key, job, self.origin, self.bundle_root, self.worker_contract
            )
        return published_run(
            cursor,
            self.source,
            self.bundle_root,
            origin=self.origin,
            execution_id=job.run_id,
        )


def published_run(cursor, source, bundle_root, *, origin, execution_id):
    """Verify publication plus all native receipts; never publish or repair here.

    The caller must separately bind the run to the active configured input. The
    publication table alone cannot establish that scheduler relationship.
    """
    run = identifier(execution_id)
    if source not in {"GitHub", "CVE", "CISA", "Ubuntu", "WA SOC"} or origin not in {
        "synthetic",
        "public",
    }:
        raise ValueError("Unsupported repository completion scope")
    root = Path(bundle_root)
    if not root.is_absolute():
        raise ValueError("Repository proof requires an absolute bundle root")
    bundle = root / run
    table = (
        "github_repository_snapshots"
        if source == "GitHub"
        else "wasoc_repository_snapshots"
        if source == "WA SOC"
        else "ubuntu_repository_snapshots"
        if source == "Ubuntu"
        else "cve_repository_snapshots"
    )
    # An absent publication is an ordinary incomplete/failed run. Do not traverse
    # its partial bundles or mistake a successful final record for a publication.
    condition = sql.SQL("run_id=%s")
    parameters = [run]
    if source != "GitHub":
        condition += sql.SQL(" AND source_name=%s")
        parameters.append(source)
    cursor.execute(
        sql.SQL(
            "SELECT origin,repository_commit,reference_observed_at,reference_payload,members "
            "FROM {} WHERE {}"
        ).format(sql.Identifier("evidence_pipeline", table), condition),
        parameters,
    )
    publication = cursor.fetchone()
    if publication is None or publication[0] != origin:
        return False
    reference = prepare(
        "ref",
        "heads/develop" if source == "CISA" else "heads/main",
        bundle / "head",
        source=source,
        origin=origin,
        replay_only=True,
    )
    if not reference.complete:
        return False
    commit = (
        github_discovery.current_commit(reference.payload)
        if source == "GitHub"
        else ubuntu_discovery.current_commit(reference.payload)
        if source in {"Ubuntu", "WA SOC"}
        else cve_discovery.current_commit(source, reference.payload)
    )
    if publication[:4] != (
        origin,
        commit,
        reference.finished_at,
        github_discovery.decode(reference.payload),
    ):
        return False
    completion = inspect_run(
        commit,
        bundle / "scan" if source == "GitHub" else bundle,
        origin=origin,
        execution_id=run,
        cursor=cursor,
        source=source,
    )
    if not completion["collection_complete"] or not completion["database_complete"]:
        return False
    members = sorted(
        (
            {"path": row["path"], "receipt_id": row["receipt_id"]}
            for row in completion["outcomes"]
        ),
        key=lambda row: row["path"],
    )
    return publication[4] == members
