"""Validated snapshot boundary shared by source adapters and transactional writers.

Transport adapters must finish pagination before marking a snapshot complete.
This module performs no network access, database mutation or agency assignment.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import json
from typing import Literal
from uuid import UUID

from .file_payload import FilePayload


MAX_RECORDS = 100_000


Origin = Literal["synthetic", "public", "lab"]
Outcome = Literal["success", "partial", "failure"]


def utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ValueError("An explicit timezone is required")
    return value.astimezone(timezone.utc)


def identifier(value: str) -> str:
    """Canonical nonzero Microsoft/shared identifiers, never hostname guesses."""
    if not isinstance(value, str):
        raise ValueError("Identifier must be text")
    parsed = UUID(value)
    if parsed.int == 0:
        raise ValueError("Zero identifier is not a device identity")
    return str(parsed)


@dataclass(frozen=True)
class SourceScope:
    connection_id: str
    source: str
    input_kind: str
    scope_reference: str
    origin: Origin
    provenance: str
    tenant_id: str | None = None

    def __post_init__(self):
        object.__setattr__(self, "connection_id", identifier(self.connection_id))
        for value in (
            self.source,
            self.input_kind,
            self.scope_reference,
            self.provenance,
        ):
            if not isinstance(value, str) or not value.strip() or len(value) > 4096:
                raise ValueError("Source metadata must be nonempty bounded text")
        if self.origin not in ("synthetic", "public", "lab"):
            raise ValueError("Unsupported evidence origin")
        if self.tenant_id is not None:
            object.__setattr__(self, "tenant_id", identifier(self.tenant_id))
        if self.source == "Windows inventory":
            prefix = "entra-device:"
            if (
                self.input_kind != "software_inventory"
                or not self.scope_reference.startswith(prefix)
                or self.scope_reference
                != prefix + identifier(self.scope_reference[len(prefix) :])
            ):
                raise ValueError(
                    "Windows inventory requires one exact Entra-device scope"
                )
        if self.source in ("Entra", "Intune", "Defender", "Windows inventory"):
            if self.tenant_id is None or self.origin == "public":
                raise ValueError(
                    "Microsoft evidence requires a synthetic or lab tenant"
                )
        elif self.origin == "lab" and not (
            self.source == "Microsoft Update Catalog"
            and self.input_kind == "catalog_targets"
            and self.scope_reference == "triagemate:catalog/missing-patches"
            and self.tenant_id is None
        ):
            # The exact Catalog target job retains private Microsoft snapshot
            # bindings, not Catalog evidence. Its child source imports are public.
            raise ValueError(
                "Lab evidence is limited to Microsoft inputs and private Catalog target jobs"
            )


@dataclass(frozen=True)
class Snapshot:
    scope: SourceScope
    execution_id: str
    started_at: datetime
    finished_at: datetime
    outcome: Outcome
    complete: bool
    # Immutable wire bytes preserve the exact input independently of normalized hashes.
    payload: bytes
    error_code: str | None = None

    def __post_init__(self):
        if not isinstance(self.scope, SourceScope):
            raise ValueError("A validated source scope is required")
        object.__setattr__(self, "execution_id", identifier(self.execution_id))
        object.__setattr__(self, "started_at", utc(self.started_at))
        object.__setattr__(self, "finished_at", utc(self.finished_at))
        if self.finished_at < self.started_at:
            raise ValueError("Collection cannot finish before it starts")
        if self.outcome not in ("success", "partial", "failure"):
            raise ValueError("Unknown collection outcome")
        if type(self.complete) is not bool:
            raise ValueError("Completeness must be a boolean")
        if self.complete != (self.outcome == "success"):
            raise ValueError("Only fully successful snapshots may be complete")
        if self.error_code is not None and (
            not isinstance(self.error_code, str)
            or not self.error_code
            or len(self.error_code) > 128
            or not all(
                c.isascii() and (c.isalnum() or c == "_") for c in self.error_code
            )
        ):
            raise ValueError("Use a bounded safe error code, not raw provider errors")
        if self.outcome == "success" and self.error_code is not None:
            raise ValueError("Successful collection cannot contain an error code")
        if not isinstance(self.payload, bytes):
            raise ValueError("Snapshot payload must be immutable bytes")
        # Failed transport/validation responses can be non-JSON. Their bounded
        # bytes supply a fingerprint only; they must never become observations.
        if self.complete:
            self.records()

    def records(self) -> list[dict]:
        def reject_constant(value):
            raise ValueError("Nonfinite JSON number")

        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("Duplicate JSON key")
                result[key] = value
            return result

        try:
            records = json.loads(
                self.payload.decode("utf-8"),
                parse_constant=reject_constant,
                parse_float=Decimal,
                object_pairs_hook=unique_object,
            )
        except (UnicodeError, RecursionError) as exc:
            raise ValueError("Invalid JSON payload") from exc
        if not isinstance(records, list) or len(records) > MAX_RECORDS:
            raise ValueError("Snapshot must contain a bounded record array")
        if any(not isinstance(record, dict) for record in records):
            raise ValueError("Each source record must be an object")
        return records

    @property
    def input_fingerprint(self) -> str:
        return hashlib.sha256(self.payload).hexdigest()


def select_current(snapshots: list[Snapshot], scope: SourceScope) -> Snapshot | None:
    """Provisional full-snapshot policy; deltas cannot use this selector.

    Complete empty collections are legitimate snapshots. Failed or partial
    attempts do not supersede an earlier complete success. Connections and scope
    metadata must agree, rather than treating a tenant as an agency.
    """
    candidates = [item for item in snapshots if item.scope == scope and item.complete]
    return max(
        candidates,
        key=lambda item: (item.finished_at, item.started_at, item.execution_id),
        default=None,
    )


@dataclass(frozen=True)
class PublicDownload:
    url: str
    started_at: datetime
    finished_at: datetime
    wire: bytes
    payload: bytes

    @property
    def wire_fingerprint(self):
        if isinstance(self.wire, FilePayload):
            return self.wire.fingerprint
        return hashlib.sha256(self.wire).hexdigest()
