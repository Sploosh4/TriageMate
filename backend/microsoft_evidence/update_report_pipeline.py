"""Policy-scoped Intune status for the PostgreSQL evidence workspace."""

from datetime import datetime, timezone
import json

from standalone.evidence_pipeline.contracts import (
    MAX_RECORDS,
    Snapshot,
    identifier,
)
from standalone.evidence_pipeline.parsing.devices import normalize_devices
from standalone.evidence_pipeline.parsing.update_status import normalize_update_status

from .intune_report_transport import (
    IntuneUpdateReportExport,
    _authority_scope_sha256,
)
from .pipeline import connection_scope, device_binding

POLICY_SCOPE_PREFIX = "intune-quality-update-policy:"


def policy_id(scope):
    """One immutable connection scope per policy, never an implied tenant total."""
    if (scope.source, scope.input_kind, scope.origin) != (
        "Intune",
        "update_status",
        "lab",
    ):
        raise ValueError("Update reports require a dedicated Intune lab status scope")
    if not scope.scope_reference.startswith(POLICY_SCOPE_PREFIX):
        raise ValueError("Update-report scope must explicitly identify its policy")
    reference = scope.scope_reference[len(POLICY_SCOPE_PREFIX) :]
    parts = reference.split(":group:")
    if len(parts) > 2 or (len(parts) == 2 and identifier(parts[1]) != parts[1]):
        raise ValueError("Update-report isolation group must be canonical")
    value = parts[0]
    if identifier(value) != value:
        raise ValueError("Update-report policy identifier must be canonical")
    return value


def isolation_group_id(scope):
    policy_id(scope)
    parts = scope.scope_reference.split(":group:")
    if len(parts) != 2:
        raise ValueError(
            "Fresh lab reports require an explicitly pinned isolation group"
        )
    return parts[1]


def collect_update_status(
    *,
    scope,
    execution_id,
    device_snapshot,
    prepared,
    transport,
    now=lambda: datetime.now(timezone.utc),
):
    """Retain report facts only; no patch installation or CVE-resolution claim."""
    policy = policy_id(scope)
    device_binding(scope, device_snapshot, source="Intune")
    devices = normalize_devices(device_snapshot)
    if prepared.scope != connection_scope(scope, cloud=prepared.scope.cloud):
        raise ValueError("Update-report authority differs from its connection")
    if prepared.endpoint.path_template != "/beta/deviceManagement/reports/exportJobs":
        raise ValueError("Update report requires the retained export endpoint")
    started = now()
    export = IntuneUpdateReportExport.model_validate(transport.collect(policy))
    if (
        export.policy_id != policy
        or export.authority_scope_sha256 != _authority_scope_sha256(prepared.scope)
    ):
        raise ValueError("Update report differs from its policy or authority scope")
    finished = now()
    if not started <= export.observed_at <= finished:
        raise ValueError("Update report observation is outside this collection")
    encoded = []
    for page in export.result.pages:
        for raw in page.records:
            if raw.get("PolicyId") != policy:
                raise ValueError("Update report contains another policy")
            # This workspace does not retain user principal names.
            raw = {key: value for key, value in raw.items() if key != "UPN"}
            value = json.dumps(
                raw, ensure_ascii=False, separators=(",", ":"), allow_nan=False
            ).encode()
            if len(encoded) >= MAX_RECORDS:
                raise ValueError("Update report exceeds retained snapshot bounds")
            encoded.append(value)
    snapshot = Snapshot(
        scope,
        execution_id,
        started,
        finished,
        "success",
        True,
        b"[" + b",".join(encoded) + b"]",
    )
    normalize_update_status(snapshot, {device.native_id for device in devices})
    return snapshot
