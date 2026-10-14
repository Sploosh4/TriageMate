"""Read-only Windows collection with a pinned, committed device prerequisite."""

from contextlib import closing, contextmanager
from dataclasses import dataclass
import hashlib
import math
from pathlib import Path

from standalone.evidence_pipeline.collection import snapshot_bundle
from standalone.evidence_pipeline.contracts import SourceScope, identifier
from standalone.evidence_pipeline.parsing.devices import normalize_devices
from standalone.evidence_pipeline.runtime import connect
from standalone.windows_inventory import bundle, transport
from standalone.windows_inventory.contract import DeviceBinding
from standalone.windows_inventory.snapshot import verify_binding
from standalone.windows_inventory.staging import stage
from standalone.windows_inventory.component_store import persist_inventory as persist

from .microsoft_worker import verify_committed_device


@dataclass(frozen=True)
class WindowsInventoryRecipe:
    scope: SourceScope
    bundle_root: Path
    device_scope: SourceScope
    device_root: Path
    binding: DeviceBinding
    native_device_id: str
    synthetic_input: Path | None = None
    ssh_config: Path | None = None
    ssh_host: str | None = None
    ssh_config_fingerprint: str | None = None
    timeout_seconds: float = 300

    @property
    def dependencies(self):
        return (self.device_scope.connection_id,)

    def validate(self, job):
        verify_binding(self.scope, self.binding)
        if self.scope.connection_id != identifier(job.input_id):
            raise ValueError("Inventory worker differs from scheduled input")
        identifier(job.run_id)
        if (
            self.device_scope.source not in ("Entra", "Intune", "Defender")
            or self.device_scope.input_kind != "devices"
            or self.device_scope.origin != self.scope.origin
            or self.device_scope.tenant_id != self.scope.tenant_id
        ):
            raise ValueError(
                "Inventory prerequisite must be same-tenant, same-origin devices"
            )
        if (
            len(job.prerequisite_snapshots) != 1
            or job.prerequisite_snapshots[0][0] != self.device_scope.connection_id
        ):
            raise ValueError("Inventory requires its exact device prerequisite")
        identifier(job.prerequisite_snapshots[0][1])
        if (
            not isinstance(self.native_device_id, str)
            or not self.native_device_id.strip()
            or len(self.native_device_id) > 4096
        ):
            raise ValueError("Inventory requires one provider-native device ID")
        if (
            type(self.timeout_seconds) not in (int, float)
            or not math.isfinite(self.timeout_seconds)
            or self.timeout_seconds <= 0
        ):
            raise ValueError("Inventory requires a positive finite timeout")
        network = self.scope.origin == "lab"
        if network:
            if self.synthetic_input is not None or self.ssh_config is None:
                raise ValueError(
                    "Lab inventory requires SSH without synthetic fixtures"
                )
            transport.command(self.ssh_config, self.ssh_host, self.binding)
            fingerprint = hashlib.sha256(
                snapshot_bundle._read(self.ssh_config, 131072)
            ).hexdigest()
            if fingerprint != self.ssh_config_fingerprint:
                raise ValueError(
                    "Inventory SSH configuration changed; reconfigure while Off"
                )
        elif self.synthetic_input is None or any(
            value is not None
            for value in (self.ssh_config, self.ssh_host, self.ssh_config_fingerprint)
        ):
            raise ValueError(
                "Synthetic inventory requires a fixture without SSH authority"
            )
        for path in (
            self.bundle_root,
            self.device_root,
            self.synthetic_input,
            self.ssh_config,
        ):
            if path is not None and (
                not isinstance(path, Path) or not path.is_absolute()
            ):
                raise ValueError("Inventory worker paths must be absolute")
        snapshot_bundle._private_directory(self.bundle_root)
        snapshot_bundle._private_directory(self.device_root)

    def verify_registration(self):
        expected = (
            self.device_scope.connection_id,
            self.native_device_id,
            self.binding.machine_guid,
            self.binding.device_id,
            self.scope.source,
            self.scope.input_kind,
            self.scope.scope_reference,
            self.scope.tenant_id,
            self.scope.origin,
            "evidence-pipeline-v1:"
            + self.scope.origin
            + ":"
            + hashlib.sha256(self.scope.provenance.encode()).hexdigest(),
        )
        with closing(connect()) as connection, connection.cursor() as cur:
            cur.execute(
                "SELECT b.device_connection_id::text,b.native_device_id,b.machine_guid::text,b.entra_device_id::text,"
                "c.source_name,c.input_kind,c.scope_reference,t.external_tenant_id,a.origin,c.collector_reference "
                "FROM evidence_pipeline.windows_inventory_bindings b "
                "JOIN evidence.source_connections c ON c.id=b.connection_id "
                "JOIN evidence.microsoft_tenants t ON t.id=c.tenant_id "
                "JOIN evidence_pipeline.authorized_connections a ON a.connection_id=c.id WHERE c.id=%s",
                (self.scope.connection_id,),
            )
            if cur.fetchone() != expected:
                raise ValueError(
                    "Inventory configuration differs from registered authority"
                )

    def collect(self, job):
        self.validate(job)
        self.verify_registration()
        run_id = job.prerequisite_snapshots[0][1]
        if not (self.device_root / run_id).is_dir():
            raise ValueError("Inventory device prerequisite bundle is missing")

        def no_fetch():
            raise ValueError("Inventory cannot collect its prerequisite during replay")

        device = snapshot_bundle.prepare(
            self.device_scope, run_id, self.device_root, collect=no_fetch
        )
        verify_committed_device(device)
        selected = [
            record
            for record in normalize_devices(device)
            if record.native_id == self.native_device_id
            and record.registration_id == self.binding.device_id
        ]
        if len(selected) != 1:
            raise ValueError(
                "Inventory device is absent or ambiguous in its prerequisite"
            )

        @contextmanager
        def collect():
            if self.synthetic_input is not None:
                with (
                    bundle._payload(self.synthetic_input) as stream,
                    stage(stream, self.binding) as staged,
                ):
                    yield staged
            else:
                with transport.collect(
                    self.ssh_config,
                    self.ssh_host,
                    self.binding,
                    timeout_seconds=self.timeout_seconds,
                ) as staged:
                    yield staged

        with bundle.prepare(
            self.scope,
            job.run_id,
            self.bundle_root,
            self.binding,
            run_id,
            collect=collect,
        ) as (attempt, staged):
            with closing(connect()) as connection, connection:
                result = persist(
                    connection,
                    attempt,
                    staged=staged,
                    device_attempt_id=run_id if attempt.complete else None,
                )
            return {
                **result,
                "outcome": attempt.outcome,
                "attempt_id": attempt.execution_id,
            }
