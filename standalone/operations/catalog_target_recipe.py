"""Explicit dependent Catalog worker; lab bindings remain local to the parent."""

from contextlib import closing
from dataclasses import dataclass
import json
from pathlib import Path

from standalone.evidence_pipeline.contracts import SourceScope, identifier
from standalone.evidence_pipeline.runtime import connect
from standalone.evidence_pipeline.collection.snapshot_bundle import (
    _private_directory,
    _read,
)
from .catalog_target_proof import ScheduledCatalogTargets
from .catalog_target_worker import collect_targets

REFERENCE = "triagemate:catalog/missing-patches"


@dataclass(frozen=True)
class CatalogTargetRecipe:
    scope: SourceScope
    bundle_root: Path
    dependencies: tuple[str, ...]
    synthetic_input: Path | None = None
    allow_network: bool = False
    target_limit: int = 100
    record_limit: int = 10
    pass_limit: int = 10
    worker_contract: str | None = None

    def binding(self):
        return ScheduledCatalogTargets(
            self.scope.connection_id,
            self.worker_contract,
            self.scope.origin,
            self.bundle_root,
            self.dependencies,
            self.target_limit,
            self.record_limit,
            self.pass_limit,
        )

    def validate(self, job):
        if (
            not isinstance(self.scope, SourceScope)
            or self.scope.source != "Microsoft Update Catalog"
            or self.scope.input_kind != "catalog_targets"
            or self.scope.scope_reference != REFERENCE
            or self.scope.tenant_id is not None
            or job.input_id != self.scope.connection_id
            or self.scope.origin not in {"synthetic", "lab"}
            or type(self.allow_network) is not bool
        ):
            raise ValueError("Invalid dependent Catalog scope")
        identifier(job.run_id)
        ScheduledCatalogTargets(
            self.scope.connection_id,
            self.worker_contract or "0" * 64,
            self.scope.origin,
            self.bundle_root,
            self.dependencies,
            self.target_limit,
            self.record_limit,
            self.pass_limit,
        )
        if len(job.prerequisite_snapshots) != len(self.dependencies) or {
            key for key, _ in job.prerequisite_snapshots
        } != set(self.dependencies):
            raise ValueError("Catalog target prerequisite binding differs")
        for _, run in job.prerequisite_snapshots:
            identifier(run)
        if self.scope.origin == "synthetic":
            if self.allow_network or self.synthetic_input is None:
                raise ValueError("Synthetic Catalog targets require offline fixtures")
        elif not self.allow_network or self.synthetic_input is not None:
            raise ValueError(
                "Lab-derived public queries require explicit network authority"
            )
        _private_directory(self.bundle_root)
        if self.synthetic_input is not None and (
            not isinstance(self.synthetic_input, Path)
            or not self.synthetic_input.is_absolute()
        ):
            raise ValueError("Synthetic Catalog fixture path must be absolute")

    def fixtures(self):
        if self.synthetic_input is None:
            return None
        from .configuration import unique_fields
        from .checkpoint import keys

        document = json.loads(
            _read(self.synthetic_input), object_pairs_hook=unique_fields
        )
        keys(document, ["origin", "searches"])
        searches = document["searches"]
        if (
            document["origin"] != "synthetic"
            or not isinstance(searches, dict)
            or len(searches) > self.target_limit
        ):
            raise ValueError("Explicit bounded synthetic Catalog searches required")
        result = {}
        for kb, entry in searches.items():
            from .catalog_worker import fixture_data

            result[kb] = fixture_data(entry, kb)
        return result

    def collect(self, job, service_key):
        self.validate(job)
        binding = self.binding()
        with closing(connect()) as conn, conn, conn.cursor() as cursor:
            binding.active(cursor, service_key, job)
        result = collect_targets(
            self.bundle_root,
            run_id=job.run_id,
            snapshots=dict(job.prerequisite_snapshots),
            origin=self.scope.origin,
            allow_network=self.allow_network,
            fixtures=self.fixtures(),
            target_limit=self.target_limit,
            record_limit=self.record_limit,
            pass_limit=self.pass_limit,
        )
        if not result["complete"]:
            return False
        with closing(connect()) as conn, conn, conn.cursor() as cursor:
            binding.seal(cursor, service_key, job)
        return True
