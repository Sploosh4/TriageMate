"""Microsoft collection with durable, exact device prerequisites.

Synthetic inputs use native source fixtures. An explicitly constructed network
recipe delegates to the existing lab collector with frozen configuration. Both
modes require explicit operational configuration.
Imports retain the existing restricted writers and durable bundle format.
"""

from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path

from standalone.evidence_pipeline.device_binding import device_binding
from standalone.evidence_pipeline import commands
from standalone.evidence_pipeline.collection import snapshot_bundle
from standalone.evidence_pipeline.runtime import connect
from standalone.evidence_pipeline.contracts import (
    Snapshot,
    SourceScope,
    identifier,
)


INDEPENDENT = {
    ("Entra", "devices"),
    ("Intune", "devices"),
    ("Defender", "devices"),
    ("Defender", "vulnerability_catalogue"),
}
DEPENDENT = {
    ("Intune", "software"),
    ("Intune", "update_status"),
    ("Defender", "findings"),
    ("Defender", "missing_patches"),
    ("Defender", "antivirus"),
    ("Defender", "recommendations"),
    ("Defender", "vulnerability_baseline"),
    ("Defender", "vulnerability_events"),
}


def verify_committed_device(snapshot):
    with closing(connect()) as conn, conn, conn.cursor() as cur:
        cur.execute("SELECT pg_advisory_xact_lock(731904217)")
        cur.execute(
            "SELECT connection_id::text,complete,outcome,input_fingerprint,started_at,finished_at "
            "FROM evidence.collection_attempts WHERE id=%s",
            (snapshot.execution_id,),
        )
        if cur.fetchone() != (
            snapshot.scope.connection_id,
            True,
            "success",
            snapshot.input_fingerprint,
            snapshot.started_at,
            snapshot.finished_at,
        ):
            raise ValueError(
                "Saved device bytes do not match committed prerequisite evidence"
            )


def delta_checkpoint(recipe, job):
    """Select the same committed predecessor ordering enforced by the writer."""
    from standalone.evidence_pipeline.persistence.assessment_store import checkpoint

    with closing(connect()) as conn, conn, conn.cursor() as cur:
        cur.execute("SELECT pg_advisory_xact_lock(731904217)")
        baseline = checkpoint(cur, recipe.baseline_scope.connection_id)
        if baseline is None or baseline[0] != job.prerequisite_snapshots[1][1]:
            raise ValueError(
                "Scheduled baseline does not match its committed checkpoint"
            )
        previous = checkpoint(cur, recipe.scope.connection_id)
        latest = max(
            [row for row in (baseline, previous) if row],
            key=lambda row: (row[2], row[0]),
        )
        return latest[0], latest[1]


def saved_delta_request(root, run_id):
    """Read a frozen request only; normal bundle replay validates its full receipt."""
    from .configuration import unique_fields
    from .checkpoint import timestamp

    metadata = json.loads(
        snapshot_bundle._read(root / run_id / "receipt.json", 131072),
        object_pairs_hook=unique_fields,
    )
    binding = metadata["binding"]
    return identifier(binding["predecessor_attempt_id"]), timestamp(
        binding["since_time"]
    )


@dataclass(frozen=True)
class MicrosoftRecipe:
    scope: SourceScope
    bundle_root: Path
    synthetic_input: Path | None
    device_scope: SourceScope | None = None
    device_root: Path | None = None
    association_input: Path | None = None
    baseline_scope: SourceScope | None = None
    network_config: Path | None = None
    association_config: Path | None = None
    network_fingerprint: str | None = None

    @property
    def dependencies(self):
        devices = (
            () if self.device_scope is None else (self.device_scope.connection_id,)
        )
        return devices + (
            () if self.baseline_scope is None else (self.baseline_scope.connection_id,)
        )

    def validate(self, job):
        if self.scope.connection_id != identifier(job.input_id):
            raise ValueError("Microsoft worker differs from scheduled input")
        identifier(job.run_id)
        key = self.scope.source, self.scope.input_kind
        network = self.network_config is not None
        if (
            self.scope.origin != ("lab" if network else "synthetic")
            or key not in INDEPENDENT | DEPENDENT
        ):
            raise ValueError("Unsupported scheduled Microsoft input")
        if network:
            if self.synthetic_input is not None or self.association_input is not None:
                raise ValueError(
                    "Network Microsoft inputs cannot use synthetic fixtures"
                )
        elif (
            self.synthetic_input is None
            or self.association_config is not None
            or self.network_fingerprint is not None
        ):
            raise ValueError(
                "Synthetic Microsoft inputs require fixtures without network policy"
            )
        if key in DEPENDENT:
            device = self.device_scope
            if (
                device is None
                or device.source != self.scope.source
                or device.input_kind != "devices"
                or device.origin != self.scope.origin
                or device.tenant_id != self.scope.tenant_id
                or self.device_root is None
            ):
                raise ValueError(
                    "Microsoft prerequisite must be same-source tenant devices"
                )
            if (
                len(job.prerequisite_snapshots) != len(self.dependencies)
                or job.prerequisite_snapshots[0][0] != device.connection_id
            ):
                raise ValueError("Exact device prerequisite is required")
            identifier(job.prerequisite_snapshots[0][1])
        elif (
            self.device_scope is not None
            or self.device_root is not None
            or job.prerequisite_snapshots
        ):
            raise ValueError("Independent Microsoft input cannot bind device evidence")
        if self.scope.input_kind == "vulnerability_events":
            baseline = self.baseline_scope
            if (
                baseline is None
                or baseline.source != "Defender"
                or baseline.input_kind != "vulnerability_baseline"
                or baseline.origin != self.scope.origin
                or baseline.tenant_id != self.scope.tenant_id
                or job.prerequisite_snapshots[1][0] != baseline.connection_id
            ):
                raise ValueError(
                    "Delta requires an exact same-tenant baseline prerequisite"
                )
            identifier(job.prerequisite_snapshots[1][1])
        elif self.baseline_scope is not None:
            raise ValueError("Only delta inputs accept a baseline prerequisite")
        associated = self.scope.input_kind in ("software", "recommendations")
        if network and associated:
            from .microsoft_network import collector

            command = collector()
            selected = (
                command.selected_software_device_id(self.scope)
                if self.scope.input_kind == "software"
                else command.selected_device_id(self.scope)
            )
            if selected is not None:
                associated = False
        if associated != (
            (self.association_config if network else self.association_input) is not None
        ):
            raise ValueError(
                "Software and recommendations require association fixtures"
            )
        for path in (
            self.synthetic_input,
            self.association_input,
            self.bundle_root,
            self.device_root,
            self.network_config,
            self.association_config,
        ):
            if path is not None and (
                not isinstance(path, Path) or not path.is_absolute()
            ):
                raise ValueError("Microsoft worker paths must be absolute")
        snapshot_bundle._private_directory(self.bundle_root)
        if self.device_root is not None:
            snapshot_bundle._private_directory(self.device_root)
        if network:
            from .microsoft_network import configurations

            configurations(self)

    def collect(self, job):
        self.validate(job)
        device = binding = None
        if self.device_scope is not None:
            run_id = job.prerequisite_snapshots[0][1]
            # Missing saved evidence cannot initiate a prerequisite fetch.
            if not (self.device_root / run_id).is_dir():
                raise ValueError("Saved device prerequisite is missing")

            def no_fetch():
                raise ValueError("Device prerequisite cannot collect during replay")

            device = snapshot_bundle.prepare(
                self.device_scope,
                run_id,
                self.device_root,
                collect=no_fetch,
            )
            binding = device_binding(self.scope, device, source=self.scope.source)
            verify_committed_device(device)

        predecessor = since = None
        if self.scope.input_kind == "vulnerability_events":
            if (self.bundle_root / job.run_id).exists():
                predecessor, since = saved_delta_request(self.bundle_root, job.run_id)
            else:
                predecessor, since = delta_checkpoint(self, job)
            binding.update(
                predecessor_attempt_id=predecessor, since_time=since.isoformat()
            )

        if self.network_config is not None:
            from .microsoft_network import collect as collect_network

            return collect_network(self, job, device, predecessor, since)

        def collect():
            started = datetime.now(timezone.utc)
            payload = b""
            associated = self.association_input is not None
            try:
                payload = snapshot_bundle._read(self.synthetic_input)
                value = Snapshot(
                    self.scope,
                    job.run_id,
                    started,
                    datetime.now(timezone.utc),
                    "success",
                    True,
                    payload,
                )
                if associated:
                    relations = snapshot_bundle._read(self.association_input)
                    snapshot_bundle._validate_associations(value, relations)
                    return value, relations
                return value
            except (ValueError, OSError):
                value = Snapshot(
                    self.scope,
                    job.run_id,
                    started,
                    datetime.now(timezone.utc),
                    "failure",
                    False,
                    payload,
                    "invalid_synthetic_microsoft_input",
                )
                return (value, None) if associated else value

        kind = self.scope.input_kind
        prepare = (
            snapshot_bundle.prepare_with_associations
            if kind == "software"
            else snapshot_bundle.prepare_recommendations
            if kind == "recommendations"
            else snapshot_bundle.prepare
        )
        value = prepare(
            self.scope, job.run_id, self.bundle_root, collect=collect, binding=binding
        )
        if kind == "devices":
            return commands.ingest(value)
        if kind == "vulnerability_catalogue":
            return commands.ingest_catalogue(value)
        if kind in ("vulnerability_baseline", "vulnerability_events"):
            from standalone.evidence_pipeline.assessment_commands import ingest

            return ingest(value, device.execution_id, predecessor, since)
        if kind == "recommendations":
            from standalone.evidence_pipeline.recommendation_commands import ingest

            return ingest(value[0], device.execution_id, value[1])
        snapshot, associations = value if kind == "software" else (value, None)
        return commands.ingest_exposure(snapshot, device.execution_id, associations)
