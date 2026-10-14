"""Stable device receipt binding shared by live and synthetic collectors."""

from dataclasses import asdict
import hashlib
import json


def device_binding(scope, device_snapshot, *, source):
    """Bind exposure evidence to a complete same-source device execution."""
    if (
        not device_snapshot.complete
        or scope.source != source
        or device_snapshot.scope.source != source
        or device_snapshot.scope.input_kind != "devices"
        or device_snapshot.scope.tenant_id != scope.tenant_id
        or device_snapshot.scope.origin != scope.origin
    ):
        raise ValueError("Exposure retries require the same complete device scope")
    return {
        "device_scope_fingerprint": hashlib.sha256(
            json.dumps(asdict(device_snapshot.scope), sort_keys=True).encode()
        ).hexdigest(),
        "device_execution_id": device_snapshot.execution_id,
        "device_connection_id": device_snapshot.scope.connection_id,
        "device_input_fingerprint": device_snapshot.input_fingerprint,
    }
