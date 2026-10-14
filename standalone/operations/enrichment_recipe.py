"""Scheduled enrichment uses explicit scope and a committed bounded batch."""

from contextlib import closing
from dataclasses import dataclass
import json
from pathlib import Path

from standalone.evidence_pipeline import enrichment_commands
from standalone.evidence_pipeline.contracts import (
    SourceScope,
    identifier,
)
from standalone.evidence_pipeline.persistence.enrichment_store import SOURCES
from standalone.evidence_pipeline.runtime import connect
from standalone.evidence_pipeline.collection.snapshot_bundle import (
    _private_directory,
    _read,
)

from .enrichment_batch import ScheduledEnrichment


@dataclass(frozen=True)
class EnrichmentRecipe:
    scope: SourceScope
    bundle_root: Path
    synthetic_input: Path | None = None
    allow_network: bool = False
    limit: int = 100
    worker_contract: str | None = None
    refresh_completed: bool = False

    def binding(self):
        from .enrichment_refresh_binding import RefreshingEnrichment

        binding_type = (
            RefreshingEnrichment if self.refresh_completed else ScheduledEnrichment
        )
        extra = (
            {"bundle_root": self.bundle_root / "refresh"}
            if self.refresh_completed
            else {}
        )
        return binding_type(
            self.scope.connection_id,
            self.worker_contract,
            self.scope.source,
            self.scope.origin,
            self.limit,
            **extra,
        )

    def validate(self, job):
        if (
            not isinstance(self.scope, SourceScope)
            or self.scope.source not in SOURCES
            or self.scope.input_kind != "enrichment_queue"
            or self.scope.scope_reference
            != "triagemate:enrichment/" + self.scope.source
            or self.scope.tenant_id is not None
            or self.scope.connection_id != identifier(job.input_id)
            or job.prerequisite_snapshots
        ):
            raise ValueError("Invalid scheduled enrichment scope")
        identifier(job.run_id)
        if type(self.refresh_completed) is not bool:
            raise ValueError("Explicit boolean refresh configuration required")
        if type(self.limit) is not int or not 1 <= self.limit <= 100:
            raise ValueError("Enrichment batch limit must be between 1 and 100")
        if type(self.allow_network) is not bool:
            raise ValueError("Explicit enrichment network authority required")
        if self.scope.origin == "synthetic":
            if self.synthetic_input is None or self.allow_network:
                raise ValueError("Synthetic enrichment requires offline fixtures")
        elif (
            self.scope.origin != "public"
            or not self.allow_network
            or self.synthetic_input is not None
        ):
            raise ValueError("Public enrichment requires explicit network opt-in")
        for path in (self.bundle_root, self.synthetic_input):
            if path is not None and (
                not isinstance(path, Path) or not path.is_absolute()
            ):
                raise ValueError("Enrichment paths must be absolute")
        _private_directory(self.bundle_root)
        if self.worker_contract is not None:
            self.binding()

    def fixtures(self):
        from .configuration import unique_fields
        from .checkpoint import keys

        if self.synthetic_input is None:
            return None
        document = json.loads(
            _read(self.synthetic_input),
            object_pairs_hook=unique_fields,
        )
        keys(
            document,
            ["origin", "requests", "refresh"]
            if self.refresh_completed
            else ["origin", "requests"],
        )
        requests = document["requests"]
        if (
            document["origin"] != "synthetic"
            or not isinstance(requests, dict)
            or len(requests) > 100
        ):
            raise ValueError("Bounded synthetic enrichment fixture required")
        if any(
            identifier(key) != key or not isinstance(value, str)
            for key, value in requests.items()
        ):
            raise ValueError(
                "Synthetic enrichment requires canonical request IDs and wire text"
            )
        return {key: value.encode() for key, value in requests.items()}

    def refresh_fixtures(self):
        from .configuration import unique_fields
        from standalone.evidence_pipeline.parsing.public_inputs import _cve

        if not self.refresh_completed or self.synthetic_input is None:
            return None
        self.fixtures()
        document = json.loads(
            _read(self.synthetic_input), object_pairs_hook=unique_fields
        )
        values = document["refresh"]
        if (
            not isinstance(values, dict)
            or len(values) > 100
            or any(
                _cve(cve) != cve or not isinstance(wire, str)
                for cve, wire in values.items()
            )
        ):
            raise ValueError("Refresh fixtures require explicit bounded CVE wires")
        return {cve: wire.encode() for cve, wire in values.items()}

    def collect(self, job, service_key):
        self.validate(job)
        binding = self.binding()
        fixtures = self.fixtures()
        refresh_fixtures = self.refresh_fixtures()
        with closing(connect()) as conn, conn, conn.cursor() as cursor:
            binding.active(cursor, service_key, job)
            existing = binding.saved(cursor, service_key, job)
        if self.allow_network and existing is None:
            enrichment_commands.continue_discovery(
                origin="public", sources=[self.scope.source], limit=100
            )
        with closing(connect()) as conn, conn, conn.cursor() as cursor:
            capacity = (
                binding.refresh().initial_capacity(
                    cursor,
                    service_key,
                    job,
                    synthetic_cves=None
                    if refresh_fixtures is None
                    else list(refresh_fixtures),
                )
                if self.refresh_completed
                else self.limit
            )
            selected = binding.declare(
                cursor,
                service_key,
                job,
                synthetic_ids=None if fixtures is None else list(fixtures),
                capacity=capacity,
            )
            if self.refresh_completed:
                binding.refresh().declare(
                    cursor,
                    service_key,
                    job,
                    capacity=self.limit - len(selected),
                    synthetic_cves=None
                    if refresh_fixtures is None
                    else list(refresh_fixtures),
                )
        # The declaration commits before any selected request is claimed or fetched.
        enrichment_commands.process_pending(
            self.bundle_root / "requests",
            limit=self.limit,
            allow_network=self.allow_network,
            synthetic_inputs=fixtures,
            sources=[self.scope.source],
            request_ids=selected,
        )
        if self.refresh_completed:
            from .enrichment_refresh_worker import collect

            refresh_root = self.bundle_root / "refresh"
            refresh_root.mkdir(mode=0o700, exist_ok=True)
            _private_directory(refresh_root)
            collect(
                binding.refresh(),
                job,
                service_key,
                refresh_root,
                allow_network=self.allow_network,
                fixtures=refresh_fixtures,
            )
        with closing(connect()) as conn, conn, conn.cursor() as cursor:
            return binding.committed(cursor, service_key, job)
