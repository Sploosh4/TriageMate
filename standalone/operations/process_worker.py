"""Supervised public and synthetic Microsoft collection in separate processes."""

from dataclasses import dataclass
import multiprocessing
import os
from pathlib import Path

from standalone.evidence_pipeline.commands import ingest_public
from standalone.evidence_pipeline.contracts import (
    SourceScope,
    identifier,
)
from standalone.evidence_pipeline.collection.public_collection import prepare
from standalone.evidence_pipeline.collection.snapshot_bundle import (
    _read,
    _private_directory,
)
from .microsoft_worker import MicrosoftRecipe
from .windows_inventory_worker import WindowsInventoryRecipe
from .repository_recipe import RepositoryRecipe
from .enrichment_recipe import EnrichmentRecipe
from .catalog_target_recipe import CatalogTargetRecipe


@dataclass(frozen=True)
class PublicRecipe:
    scope: SourceScope
    bundle_root: Path
    synthetic_input: Path | None = None
    allow_network: bool = False
    parameters: tuple[tuple[str, str], ...] = ()

    def validate(self, job):
        from standalone.evidence_pipeline.collection.collection_scope import (
            require_active_collection,
        )

        if not isinstance(
            self.scope, SourceScope
        ) or self.scope.connection_id != identifier(job.input_id):
            raise ValueError("Public worker scope differs from scheduled input")
        identifier(job.run_id)
        if job.prerequisite_snapshots:
            raise ValueError(
                "Public collection cannot bind Microsoft prerequisite snapshots"
            )
        if type(self.allow_network) is not bool or self.scope.tenant_id is not None:
            raise ValueError("Invalid public worker authority")
        if self.scope.origin == "synthetic":
            if self.synthetic_input is None or self.allow_network:
                raise ValueError(
                    "Synthetic workers require a fixture and cannot enable network"
                )
        elif (
            self.scope.origin != "public"
            or not self.allow_network
            or self.synthetic_input is not None
        ):
            raise ValueError("Public worker requires explicit network opt-in")
        allowed = {
            "cve",
            "month",
            "score_date",
            "advisory_id",
            "repository_commit",
            "repository_path",
            "vendor_path",
        }
        if not isinstance(self.parameters, tuple) or any(
            not isinstance(pair, tuple)
            or len(pair) != 2
            or pair[0] not in allowed
            or not isinstance(pair[1], str)
            for pair in self.parameters
        ):
            raise ValueError("Invalid fixed public source parameters")
        if len(dict(self.parameters)) != len(self.parameters):
            raise ValueError("Duplicate public source parameter")
        require_active_collection(
            self.scope.source, score_date=dict(self.parameters).get("score_date")
        )
        _private_directory(Path(self.bundle_root))


class ProcessHandle:
    def __init__(self, process):
        self.process = process

    def poll(self):
        return self.process.exitcode

    def cancel(self):
        if self.process.is_alive():
            self.process.terminate()


def _collect(recipe, job, service_key):
    from .worker_lease import Lease, paths, watch_cancellation
    from .supervisor import PostgresRepository

    recipe.validate(job)
    lease_path, cancel_path = paths(recipe.bundle_root, job.run_id)
    lease = Lease(lease_path)
    if not lease.acquire():
        raise SystemExit(1)
    stop = thread = None
    try:
        saved = PostgresRepository(service_key).load()
        state = None if saved is None else saved[1].inputs.get(job.input_id)
        if (
            state is None
            or state.active != job
            or os.path.lexists(cancel_path)
            or job.run_id in saved[1].control.cancel_requested
        ):
            raise SystemExit(1)
        stop, thread = watch_cancellation(recipe.bundle_root, job.run_id)
        _collect_under_lease(recipe, job, service_key)
    finally:
        if stop is not None:
            stop.set()
            thread.join()
        lease.close()


def _collect_under_lease(recipe, job, service_key=None):
    try:
        recipe.validate(job)
        if isinstance(recipe, (EnrichmentRecipe, CatalogTargetRecipe)):
            raise SystemExit(0 if recipe.collect(job, service_key) else 1)
        if isinstance(recipe, RepositoryRecipe):
            result = recipe.collect(job, service_key)
            raise SystemExit(0 if result.reason == "finished" else 1)
        if isinstance(recipe, (MicrosoftRecipe, WindowsInventoryRecipe)):
            result = recipe.collect(job)
            raise SystemExit(0 if result.get("outcome") == "success" else 1)
        payload = None
        if recipe.synthetic_input is not None:
            payload = _read(
                Path(recipe.synthetic_input),
            )
        snapshot = prepare(
            recipe.scope,
            job.run_id,
            Path(recipe.bundle_root) / job.run_id,
            synthetic_payload=payload,
            **dict(recipe.parameters),
        )
        result = ingest_public(snapshot)
        success = result.get("outcome") == "success"
    except Exception:
        # Exceptions can contain paths or source details. The supervisor checks
        # the database independently; raw exceptions do not become UI messages.
        success = False
    raise SystemExit(0 if success else 1)


def start_public(recipe, job, *, service_key):
    recipe.validate(job)
    process = multiprocessing.get_context("spawn").Process(
        target=_collect, args=(recipe, job, service_key), daemon=True
    )
    process.start()
    return ProcessHandle(process)


class PublicWorkers:
    """One local supervisor owner, with restart-safe handles for collection workers."""

    def __init__(self, service_key, recipes, directory):
        import hashlib
        from .store import service_key as validate_key
        from .worker_lease import Lease

        self.service_key = validate_key(service_key)
        self.recipes = {}
        for recipe in recipes:
            if not isinstance(
                recipe,
                (
                    PublicRecipe,
                    MicrosoftRecipe,
                    WindowsInventoryRecipe,
                    RepositoryRecipe,
                    EnrichmentRecipe,
                    CatalogTargetRecipe,
                ),
            ) or not isinstance(recipe.scope, SourceScope):
                raise ValueError("Validated collection worker recipe required")
            key = recipe.scope.connection_id
            if key in self.recipes:
                raise ValueError("Duplicate collection worker input")
            self.recipes[key] = recipe
        name = hashlib.sha256(self.service_key.encode()).hexdigest() + ".supervisor"
        self.lease = Lease(Path(directory) / name)
        if not self.lease.acquire():
            raise ValueError("This operational service already has a local supervisor")

    def __call__(self, job):
        if self.lease.descriptor is None:
            raise ValueError("Supervisor ownership has ended")
        return start_public(
            self.recipes[job.input_id], job, service_key=self.service_key
        )

    def recover(self, job):
        from .worker_lease import RecoveredHandle

        recipe = self.recipes[job.input_id]
        return RecoveredHandle(recipe.bundle_root, job.run_id)

    def close(self):
        self.lease.close()
