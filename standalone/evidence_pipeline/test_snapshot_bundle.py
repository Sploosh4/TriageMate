"""Synthetic snapshot persistence, recovery, permission and tamper checks."""

from dataclasses import replace
from datetime import datetime, timezone
import json
from uuid import uuid4

import pytest

from .contracts import Snapshot, SourceScope
from standalone.evidence_pipeline.collection.snapshot_bundle import (
    prepare,
    prepare_with_associations,
)


@pytest.fixture
def software_case(case):
    root, snapshot = case
    snapshot = replace(
        snapshot, scope=replace(snapshot.scope, source="Intune", input_kind="software")
    )
    return root, snapshot, {"device_execution_id": str(uuid4())}


def test_associated_bundle_preserves_exact_bytes_and_pin(software_case):
    root, snapshot, binding = software_case
    relations = b'{ "synthetic-app": [] }'
    args = (snapshot.scope, snapshot.execution_id, root)
    expected = (snapshot, relations)
    assert (
        prepare_with_associations(*args, binding=binding, collect=lambda: expected)
        == expected
    )
    assert (
        prepare_with_associations(
            *args,
            binding=binding,
            collect=lambda: pytest.fail("Refetched association input"),
        )
        == expected
    )
    with pytest.raises(ValueError, match="binding differs"):
        prepare_with_associations(
            *args,
            binding={"device_execution_id": str(uuid4())},
            collect=lambda: pytest.fail("Refetched changed binding"),
        )


@pytest.mark.parametrize("damage", ("changed", "missing", "permissions", "receipt"))
def test_associated_bundle_damage_never_refetches(software_case, damage):
    root, snapshot, binding = software_case
    args = (snapshot.scope, snapshot.execution_id, root)
    prepare_with_associations(*args, binding=binding, collect=lambda: (snapshot, b"{}"))
    bundle = root / snapshot.execution_id
    path = bundle / "associations.bin"
    if damage == "changed":
        path.write_bytes(b'{"new":[]}')
    elif damage == "missing":
        path.unlink()
    elif damage == "permissions":
        path.chmod(0o644)
    else:
        (bundle / "receipt.json").unlink()
    with pytest.raises((ValueError, OSError)):
        prepare_with_associations(
            *args,
            binding=binding,
            collect=lambda: pytest.fail("Refetched damaged bundle"),
        )


def test_associated_failure_replays_without_links(software_case):
    root, snapshot, binding = software_case
    snapshot = replace(
        snapshot, outcome="failure", complete=False, payload=b"", error_code="failed"
    )
    args = (snapshot.scope, snapshot.execution_id, root)
    assert prepare_with_associations(
        *args, binding=binding, collect=lambda: (snapshot, None)
    ) == (snapshot, None)
    assert prepare_with_associations(
        *args, binding=binding, collect=lambda: pytest.fail("Refetched failed bundle")
    ) == (snapshot, None)


@pytest.mark.parametrize("relations", (None, b"[]", b'{"a":[],"a":[]}'))
def test_associated_success_requires_valid_map(software_case, relations):
    root, snapshot, binding = software_case
    with pytest.raises(ValueError):
        prepare_with_associations(
            snapshot.scope,
            snapshot.execution_id,
            root,
            binding=binding,
            collect=lambda: (snapshot, relations),
        )


@pytest.fixture
def case(tmp_path):
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    scope = SourceScope(
        str(uuid4()),
        "Entra",
        "devices",
        "synthetic",
        "synthetic",
        "Explicitly synthetic records",
        str(uuid4()),
    )
    now = datetime.now(timezone.utc)
    snapshot = Snapshot(
        scope, str(uuid4()), now, now, "success", True, b'[{"id":"synthetic"}]'
    )
    return root, snapshot


def run(root, snapshot, collect=None):
    return prepare(
        snapshot.scope,
        snapshot.execution_id,
        root,
        collect=collect or (lambda: snapshot),
    )


def test_exact_snapshot_replayed_without_collecting_again(case):
    root, snapshot = case
    assert run(root, snapshot) == snapshot
    assert (
        run(root, snapshot, lambda: pytest.fail("Refetched existing snapshot"))
        == snapshot
    )
    for path in (root / snapshot.execution_id).iterdir():
        assert path.stat().st_mode & 0o077 == 0


def test_failure_outcome_survives_replay(case):
    root, snapshot = case
    snapshot = replace(
        snapshot,
        outcome="failure",
        complete=False,
        payload=b"",
        error_code="collection_failed",
    )
    assert run(root, snapshot) == snapshot
    assert (
        run(root, snapshot, lambda: pytest.fail("Retried completed failure"))
        == snapshot
    )


@pytest.mark.parametrize(
    "kind", ("payload", "scope", "permission", "symlink", "incomplete")
)
def test_invalid_bundle_never_refetches(case, kind):
    root, snapshot = case
    run(root, snapshot)
    bundle = root / snapshot.execution_id
    payload = bundle / "payload.bin"
    if kind == "payload":
        payload.write_bytes(b"changed")
    elif kind == "scope":
        snapshot = replace(
            snapshot, scope=replace(snapshot.scope, provenance="changed")
        )
    elif kind == "permission":
        payload.chmod(0o644)
    elif kind == "symlink":
        payload.unlink()
        payload.symlink_to(root / "nonexistent")
    else:
        (bundle / "receipt.json").unlink()
    with pytest.raises((ValueError, OSError)):
        run(root, snapshot, lambda: pytest.fail("Refetched invalid bundle"))


def test_collecting_different_execution_leaves_incomplete_bundle(case):
    root, snapshot = case
    with pytest.raises(ValueError, match="different snapshot"):
        run(root, snapshot, lambda: replace(snapshot, execution_id=str(uuid4())))
    with pytest.raises(FileNotFoundError):
        run(root, snapshot, lambda: pytest.fail("Refetched incomplete bundle"))


def test_unsafe_root_rejected_before_collection(case):
    root, snapshot = case
    root.chmod(0o755)
    with pytest.raises(ValueError, match="owner-only"):
        run(root, snapshot, lambda: pytest.fail("Used unsafe storage"))


def test_duplicate_receipt_fields_rejected(case):
    root, snapshot = case
    run(root, snapshot)
    receipt = root / snapshot.execution_id / "receipt.json"
    metadata = json.loads(receipt.read_text())
    receipt.write_text('{"version":1,' + json.dumps(metadata)[1:])
    with pytest.raises(ValueError, match="Duplicate"):
        run(root, snapshot)


def test_bound_bundle_preserves_inventory_and_rejects_substitution(case):
    root, snapshot = case
    binding = {
        "device_execution_id": str(uuid4()),
        "device_input_fingerprint": "a" * 64,
    }
    first = prepare(
        snapshot.scope,
        snapshot.execution_id,
        root,
        collect=lambda: snapshot,
        binding=binding,
    )
    assert (
        prepare(
            snapshot.scope,
            snapshot.execution_id,
            root,
            collect=lambda: pytest.fail("Refetched"),
            binding=binding,
        )
        == first
    )
    changed = {**binding, "device_input_fingerprint": "b" * 64}
    with pytest.raises(ValueError, match="binding differs"):
        prepare(
            snapshot.scope,
            snapshot.execution_id,
            root,
            collect=lambda: pytest.fail("Refetched"),
            binding=changed,
        )
    with pytest.raises(ValueError, match="receipt"):
        prepare(
            snapshot.scope,
            snapshot.execution_id,
            root,
            collect=lambda: pytest.fail("Refetched"),
        )


def test_binding_cannot_be_added_to_existing_unbound_bundle(case):
    root, snapshot = case
    run(root, snapshot)
    with pytest.raises(ValueError, match="receipt"):
        prepare(
            snapshot.scope,
            snapshot.execution_id,
            root,
            collect=lambda: pytest.fail("Refetched"),
            binding={"device_execution_id": str(uuid4())},
        )


def test_oversized_binding_rejected_before_creating_bundle(case):
    root, snapshot = case
    with pytest.raises(ValueError, match="Oversized snapshot binding"):
        prepare(
            snapshot.scope,
            snapshot.execution_id,
            root,
            collect=lambda: pytest.fail("Collected"),
            binding={str(i): "x" * 4096 for i in range(3)},
        )
    assert not (root / snapshot.execution_id).exists()


def test_large_snapshot_and_associations_replay_without_frontend_budget(software_case):
    root, snapshot, binding = software_case
    snapshot = replace(snapshot, payload=b" " * 45_000_001 + snapshot.payload)
    relations = b" " * 45_000_001 + b'{"synthetic-app":[]}'
    expected = snapshot, relations
    args = snapshot.scope, snapshot.execution_id, root
    assert (
        prepare_with_associations(*args, binding=binding, collect=lambda: expected)
        == expected
    )
    assert (
        prepare_with_associations(
            *args,
            binding=binding,
            collect=lambda: pytest.fail(
                "Large saved evidence must replay without refetching"
            ),
        )
        == expected
    )
