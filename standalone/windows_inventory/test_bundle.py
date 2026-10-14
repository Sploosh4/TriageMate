"""Durable exact-byte replay, authority and interrupted-write boundaries."""

from contextlib import contextmanager
from dataclasses import replace
import io
import json
from uuid import uuid4

import pytest

from .bundle import prepare
from .staging import stage
from .test_contract import BINDING, sample
from .test_snapshot import scope


def storage(tmp_path):
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    return root


def collected():
    return stage(io.BytesIO(json.dumps(sample()).encode()), BINDING)


def no_fetch():
    pytest.fail("Saved or incomplete bundle must not refetch inventory")


def test_collect_once_then_replay_exact_source_and_device_prerequisite(tmp_path):
    root, selected, execution, device = (
        storage(tmp_path),
        scope(),
        str(uuid4()),
        str(uuid4()),
    )
    with prepare(selected, execution, root, BINDING, device, collect=collected) as (
        attempt,
        staged,
    ):
        expected = list(staged.records())
        fingerprint = attempt.input_fingerprint
    with prepare(selected, execution, root, BINDING, device, collect=no_fetch) as (
        attempt,
        staged,
    ):
        assert list(staged.records()) == expected
        assert attempt.input_fingerprint == fingerprint
    for path in (root / execution).iterdir():
        assert path.stat().st_mode & 0o077 == 0


@pytest.mark.parametrize("changed", ["device-attempt", "machine", "provenance"])
def test_changed_replay_context_never_collects(tmp_path, changed):
    root, selected, execution, device = (
        storage(tmp_path),
        scope(),
        str(uuid4()),
        str(uuid4()),
    )
    with prepare(selected, execution, root, BINDING, device, collect=collected):
        pass
    binding = BINDING
    if changed == "device-attempt":
        device = str(uuid4())
    elif changed == "machine":
        binding = replace(binding, machine_guid=str(uuid4()))
    else:
        selected = replace(selected, provenance="Different synthetic provenance")
    with pytest.raises(ValueError, match="prerequisite changed"):
        with prepare(selected, execution, root, binding, device, collect=no_fetch):
            pytest.fail("Changed context accepted")


def test_modified_source_bytes_rejected_even_when_valid_json(tmp_path):
    root, selected, execution, device = (
        storage(tmp_path),
        scope(),
        str(uuid4()),
        str(uuid4()),
    )
    with prepare(selected, execution, root, BINDING, device, collect=collected):
        pass
    payload = root / execution / "payload.bin"
    payload.write_bytes(payload.read_bytes() + b" ")
    with pytest.raises(ValueError, match="differs from its receipt"):
        with prepare(selected, execution, root, BINDING, device, collect=no_fetch):
            pytest.fail("Modified payload accepted")


def test_incomplete_bundle_requires_explicit_recovery(tmp_path):
    root, selected, execution, device = (
        storage(tmp_path),
        scope(),
        str(uuid4()),
        str(uuid4()),
    )
    (root / execution).mkdir(mode=0o700)
    with pytest.raises(FileNotFoundError):
        with prepare(selected, execution, root, BINDING, device, collect=no_fetch):
            pytest.fail("Incomplete bundle accepted")


def test_timeout_persists_safe_failure_and_replay_does_not_retry(tmp_path):
    root, selected, execution, device = (
        storage(tmp_path),
        scope(),
        str(uuid4()),
        str(uuid4()),
    )

    @contextmanager
    def timeout():
        raise TimeoutError("private provider details")
        yield

    with prepare(selected, execution, root, BINDING, device, collect=timeout) as (
        attempt,
        staged,
    ):
        assert not attempt.complete and staged is None
        assert attempt.error_code == "inventory_timeout"
    assert (
        "private provider details"
        not in (root / execution / "receipt.json").read_text()
    )
    with prepare(selected, execution, root, BINDING, device, collect=no_fetch) as (
        attempt,
        staged,
    ):
        assert not attempt.complete and staged is None


def test_save_interruption_closes_staging_without_claiming_complete_bundle(tmp_path):
    root, selected, execution, device = (
        storage(tmp_path),
        scope(),
        str(uuid4()),
        str(uuid4()),
    )
    retained = []

    @contextmanager
    def collect():
        with collected() as staged:
            retained.append(staged.records_file)
            yield staged

    with pytest.raises(ValueError, match="save cancelled"):
        with prepare(
            selected,
            execution,
            root,
            BINDING,
            device,
            collect=collect,
            cancelled=lambda: True,
        ):
            pytest.fail("Cancelled save accepted")
    assert retained[0].closed
    assert not (root / execution / "receipt.json").exists()
    with pytest.raises(FileNotFoundError):
        with prepare(selected, execution, root, BINDING, device, collect=no_fetch):
            pytest.fail("Interrupted save refetched")


def test_symlink_and_readable_by_others_storage_rejected(tmp_path):
    root, selected, execution, device = (
        storage(tmp_path),
        scope(),
        str(uuid4()),
        str(uuid4()),
    )
    root.chmod(0o755)
    with pytest.raises(ValueError, match="owner-only"):
        with prepare(selected, execution, root, BINDING, device, collect=no_fetch):
            pytest.fail("Public storage accepted")
    root.chmod(0o700)
    alias = tmp_path / "alias"
    alias.symlink_to(root)
    with pytest.raises(ValueError, match="symlinks"):
        with prepare(selected, execution, alias, BINDING, device, collect=no_fetch):
            pytest.fail("Symlink storage accepted")
