"""Local collection controls; SQL-query authority never changes lifecycle state."""

from datetime import datetime, timezone
from contextlib import closing
from pathlib import Path
import threading
import time

from app.services.postgres_query import QueryError
from standalone.evidence_pipeline.commands import register
from standalone.evidence_pipeline.collection.snapshot_bundle import _private_directory
from standalone.operations.configuration import load
from standalone.operations.certificates import CertificateMonitor
from standalone.operations.process_worker import PublicWorkers
from standalone.operations.service import Service
from standalone.operations.supervisor import PostgresRepository
from standalone.operations.repository_recipe import RepositoryRecipe
from standalone.operations.catalog_target_recipe import CatalogTargetRecipe
from standalone.operations.repository_proof import ScheduledRepository
from standalone.operations.enrichment_recipe import EnrichmentRecipe
from standalone.operations.provider_monitor import ProviderMonitor
from standalone.operations.storage_monitor import StorageMonitor
from standalone.operations.windows_inventory_worker import WindowsInventoryRecipe


def create_service(directory, configuration_path, service_key):
    root = Path(directory) / "operations"
    root.mkdir(mode=0o700, exist_ok=True)
    _private_directory(root)
    configured = load(configuration_path, now=datetime.now(timezone.utc))
    workers = PublicWorkers(service_key, configured.recipes, root)
    try:
        service = Service(
            PostgresRepository(
                service_key,
                repository_proofs=[
                    ScheduledRepository(
                        recipe.scope.connection_id,
                        configured.state.definitions[
                            recipe.scope.connection_id
                        ].worker_contract,
                        recipe.scope.source,
                        recipe.scope.origin,
                        recipe.bundle_root,
                        recipe.kb,
                        recipe.starting_month,
                        recipe.retained_ids,
                    )
                    for recipe in configured.recipes
                    if isinstance(recipe, RepositoryRecipe)
                ],
                catalog_target_proofs=[
                    recipe.binding()
                    for recipe in configured.recipes
                    if isinstance(recipe, CatalogTargetRecipe)
                ],
                enrichment_proofs=[
                    recipe.binding()
                    for recipe in configured.recipes
                    if isinstance(recipe, EnrichmentRecipe)
                ],
            ),
            configured.state,
            workers,
            certificate_monitor=CertificateMonitor(
                service_key, configured.certificates
            ),
            provider_monitor=ProviderMonitor(service_key, configured.provider_policies),
            storage_monitor=StorageMonitor(service_key, configured.storage_policy),
        )
        for recipe in sorted(
            configured.recipes, key=lambda item: len(getattr(item, "dependencies", ()))
        ):
            if isinstance(
                recipe, (RepositoryRecipe, EnrichmentRecipe, CatalogTargetRecipe)
            ):
                # Repository input IDs identify scheduler jobs. Individual native
                # records register their own source connections during import.
                continue
            dependencies = getattr(recipe, "dependencies", ())
            if isinstance(recipe, WindowsInventoryRecipe):
                from standalone.windows_inventory.store import (
                    register as register_inventory,
                )
                from standalone.evidence_pipeline.runtime import local_database

                with closing(local_database().connect()) as connection, connection:
                    register_inventory(
                        connection,
                        recipe.scope,
                        recipe.binding,
                        recipe.device_scope.connection_id,
                        recipe.native_device_id,
                    )
                continue
            register(
                recipe.scope,
                dependencies[0] if dependencies else None,
                dependencies[1] if len(dependencies) > 1 else None,
            )
        service.start()
        return service
    except Exception:
        workers.close()
        raise


class OperationsAPI:
    def __init__(
        self,
        directory,
        configuration_path=None,
        service_key="local",
        *,
        factory=create_service,
    ):
        self.arguments = directory, configuration_path, service_key
        self.factory = factory
        self.service = None
        self.closed = False
        self.lock = threading.Lock()
        self.retry_at = 0.0
        self._open()

    def _open(self, *, force=False):
        if self.service is not None or self.closed:
            return
        if not force and time.monotonic() < self.retry_at:
            return
        self.retry_at = time.monotonic() + 5
        try:
            self.service = self.factory(*self.arguments)
        except Exception:
            # Configuration/database exceptions may contain local paths or source
            # details. Keep the rest of the workspace usable and expose failure.
            self.service = None

    def read(self):
        # Recover an unavailable startup without requiring a mode change or a
        # process restart. The lock and cooldown bound concurrent UI polling.
        if self.service is None and self.lock.acquire(blocking=False):
            try:
                self._open()
            finally:
                self.lock.release()
        if self.service is None:
            return dict(
                available=False,
                state="unavailable",
                desired=None,
                active=None,
                configured_inputs=None,
                revision=None,
                recovery_required=True,
                inputs=[],
                error="Collection controls are unavailable. Check local operations configuration and database access, then retry.",
            )
        return self.service.status()

    def notifications(self):
        from standalone.operations.notifications import load

        try:
            return load(self.arguments[2])
        except Exception:
            raise QueryError(
                "Operational notifications could not be loaded. Retry shortly.",
                503,
                "operational_notifications_unavailable",
            ) from None

    def save(self, body):
        if (
            not isinstance(body, dict)
            or set(body) != {"mode"}
            or body["mode"] not in ("running", "off", "maintenance")
        ):
            raise QueryError(
                "Choose running, off or maintenance.", 400, "invalid_operation_mode"
            )
        if not self.lock.acquire(blocking=False):
            raise QueryError(
                "Collection controls are busy. Retry shortly.", 409, "operations_busy"
            )
        try:
            if self.closed:
                raise QueryError(
                    "Collection controls are shutting down.",
                    503,
                    "operations_unavailable",
                )
            self._open(force=True)
            if self.service is None:
                raise QueryError(self.read()["error"], 503, "operations_unavailable")
            try:
                return self.service.request_mode(body["mode"])
            except Exception:
                raise QueryError(
                    "Collection state could not be confirmed. Refresh its status before retrying.",
                    503,
                    "operations_unconfirmed",
                ) from None
        finally:
            self.lock.release()

    def close(self):
        with self.lock:
            self.closed = True
        if self.service is None:
            return True
        deadline = (
            time.monotonic() + self.service.supervisor.state.control.grace_seconds + 5
        )
        while time.monotonic() < deadline:
            if self.service.close(timeout=min(5, max(0, deadline - time.monotonic()))):
                return True
        return False
