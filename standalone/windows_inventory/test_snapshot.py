"""Distinct tenant/device scope and exact attempt identity without Intune relabeling."""

from dataclasses import replace
import io
import json
from uuid import uuid4

import pytest

from standalone.evidence_pipeline.contracts import SourceScope

from .snapshot import InventoryAttempt, verify_binding
from .staging import stage
from .test_contract import BINDING, sample


def scope():
    return SourceScope(
        str(uuid4()),
        "Windows inventory",
        "software_inventory",
        "entra-device:" + BINDING.device_id,
        "synthetic",
        "TriageMate generated synthetic Windows inventory",
        BINDING.tenant_id,
    )


def test_attempt_binds_exact_staged_bytes_and_scope():
    selected = scope()
    verify_binding(selected, BINDING)
    with stage(io.BytesIO(json.dumps(sample()).encode()), BINDING) as staged:
        attempt = InventoryAttempt.from_staged(selected, str(uuid4()), staged)
        assert attempt.input_fingerprint == staged.fingerprint
        assert attempt.scope.source == "Windows inventory"
        assert attempt.complete and attempt.error_code is None
        assert attempt.finished_at >= attempt.started_at
        for changed in (
            replace(selected, tenant_id=str(uuid4())),
            replace(selected, scope_reference="entra-device:" + str(uuid4())),
        ):
            with pytest.raises(ValueError, match="differs"):
                InventoryAttempt.from_staged(changed, str(uuid4()), staged)
            with pytest.raises(ValueError, match="configured device"):
                verify_binding(changed, BINDING)


@pytest.mark.parametrize(
    "changes",
    [
        dict(origin="public"),
        dict(tenant_id=None),
        dict(input_kind="devices"),
        dict(input_kind="software"),
        dict(scope_reference="all-devices"),
        dict(scope_reference="entra-device:00000000-0000-0000-0000-000000000000"),
    ],
)
def test_invalid_inventory_scope_cannot_expand_authority(changes):
    with pytest.raises(ValueError):
        replace(scope(), **changes)


@pytest.mark.parametrize(
    "changes",
    [
        dict(input_fingerprint="bad"),
        dict(complete=1),
        dict(outcome="failure"),
        dict(error_code="private details"),
        dict(execution_id="bad"),
    ],
)
def test_invalid_attempt_rejected(changes):
    with stage(io.BytesIO(json.dumps(sample()).encode()), BINDING) as staged:
        attempt = InventoryAttempt.from_staged(scope(), str(uuid4()), staged)
        with pytest.raises(ValueError):
            replace(attempt, **changes)


def test_failure_attempt_has_safe_code_and_no_success_claim():
    with stage(io.BytesIO(json.dumps(sample()).encode()), BINDING) as staged:
        attempt = InventoryAttempt.from_staged(scope(), str(uuid4()), staged)
        failed = replace(
            attempt, complete=False, outcome="failure", error_code="inventory_timeout"
        )
        assert not failed.complete
        with pytest.raises(ValueError, match="safe error"):
            replace(failed, error_code=None)
