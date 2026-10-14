"""Immutable attempt metadata for streamed Windows inventory persistence."""

from dataclasses import dataclass
from datetime import datetime
import re

from standalone.evidence_pipeline.contracts import SourceScope, identifier, utc

from .contract import DeviceBinding
from .staging import StagedInventory


@dataclass(frozen=True)
class InventoryAttempt:
    scope: SourceScope
    execution_id: str
    started_at: datetime
    finished_at: datetime
    input_fingerprint: str
    outcome: str = "success"
    complete: bool = True
    error_code: str | None = None

    def __post_init__(self):
        if not isinstance(self.scope, SourceScope) or (
            self.scope.source,
            self.scope.input_kind,
        ) != ("Windows inventory", "software_inventory"):
            raise ValueError("Windows inventory requires its distinct source scope")
        object.__setattr__(self, "execution_id", identifier(self.execution_id))
        object.__setattr__(self, "started_at", utc(self.started_at))
        object.__setattr__(self, "finished_at", utc(self.finished_at))
        if self.finished_at < self.started_at:
            raise ValueError("Inventory cannot finish before it starts")
        if not isinstance(self.input_fingerprint, str) or not re.fullmatch(
            r"[0-9a-f]{64}", self.input_fingerprint
        ):
            raise ValueError("Inventory requires an exact source fingerprint")
        if (
            type(self.complete) is not bool
            or self.outcome not in ("success", "failure")
            or self.complete != (self.outcome == "success")
        ):
            raise ValueError("Inventory attempt outcome and completeness differ")
        if self.complete and self.error_code is not None:
            raise ValueError("Successful inventory cannot have an error code")
        if not self.complete and (
            not isinstance(self.error_code, str)
            or not re.fullmatch(r"[a-z][a-z0-9_]{0,127}", self.error_code)
        ):
            raise ValueError("Failed inventory requires a safe error code")

    @classmethod
    def from_staged(cls, scope, execution_id, staged: StagedInventory):
        if not isinstance(staged, StagedInventory):
            raise ValueError("Validated inventory staging is required")
        data = staged.metadata
        if scope.tenant_id != identifier(
            data["tenant_id"]
        ) or scope.scope_reference != "entra-device:" + identifier(data["device_id"]):
            raise ValueError("Inventory evidence differs from its source scope")
        return cls(
            scope,
            execution_id,
            datetime.fromisoformat(data["started_at"]),
            datetime.fromisoformat(data["finished_at"]),
            staged.fingerprint,
        )


def verify_binding(scope: SourceScope, binding: DeviceBinding):
    if (
        scope.source != "Windows inventory"
        or scope.input_kind != "software_inventory"
        or scope.tenant_id != binding.tenant_id
        or scope.scope_reference != "entra-device:" + binding.device_id
    ):
        raise ValueError("Inventory connection does not match its configured device")
