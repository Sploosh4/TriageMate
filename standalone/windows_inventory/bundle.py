"""Private, durable Windows inventory evidence; replay never opens SSH."""

from contextlib import contextmanager, ExitStack
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat

from standalone.evidence_pipeline.contracts import identifier
from standalone.evidence_pipeline.collection.snapshot_bundle import (
    _private_directory,
    _read,
    _sync_directory,
    _write,
)

from .contract import DeviceBinding, _unique
from .snapshot import InventoryAttempt, verify_binding
from .staging import stage


EMPTY_HASH = hashlib.sha256(b"").hexdigest()


@contextmanager
def _payload(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_mode & 0o077
            or info.st_uid != os.getuid()
        ):
            raise ValueError(
                "Inventory bundle payload must be an owner-only regular file"
            )
        yield stream


def _save_payload(path, staged, cancelled):
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    with os.fdopen(descriptor, "wb") as stream:
        staged.source_file.seek(0)
        checksum = hashlib.sha256()
        while True:
            if cancelled():
                raise ValueError("Inventory bundle save cancelled")
            chunk = staged.source_file.read(65536)
            if not chunk:
                break
            checksum.update(chunk)
            stream.write(chunk)
        if checksum.hexdigest() != staged.fingerprint:
            raise ValueError("Inventory staged source bytes changed")
        stream.flush()
        os.fsync(stream.fileno())


@contextmanager
def prepare(
    scope,
    execution_id,
    root,
    binding: DeviceBinding,
    device_attempt_id,
    *,
    collect,
    cancelled=lambda: False,
    now=lambda: datetime.now(timezone.utc),
):
    """Collect once or validate/replay the exact persisted execution and device.

    `collect` returns a context manager yielding validated inventory. Expected
    transport/validation failures retain a safe failed attempt, never partial
    observations or raw stderr. Interrupted persistence leaves an incomplete
    bundle which cannot silently recollect. This follows the existing explicit
    incomplete-bundle recovery boundary. Anonymous collector scratch is closed
    by the collector context; durable evidence is not deleted by this adapter.
    """
    verify_binding(scope, binding)
    execution_id = identifier(execution_id)
    device_attempt_id = identifier(device_attempt_id)
    root = Path(root).absolute()
    if root.resolve() != root:
        raise ValueError("Inventory bundle storage cannot traverse symlinks")
    _private_directory(root)
    directory = root / execution_id
    try:
        directory.mkdir(mode=0o700)
    except FileExistsError:
        _private_directory(directory)
    else:
        _sync_directory(root)
        started = now()
        # Only collection failures become failed attempts. A persistence failure
        # cannot masquerade as a complete saved bundle or trigger another fetch.
        with ExitStack() as contexts:
            try:
                staged = contexts.enter_context(collect())
            except (ValueError, OSError, TimeoutError) as exc:
                attempt = InventoryAttempt(
                    scope,
                    execution_id,
                    started,
                    now(),
                    EMPTY_HASH,
                    "failure",
                    False,
                    "inventory_timeout"
                    if isinstance(exc, TimeoutError)
                    else "inventory_collection_failed",
                )
                _write(directory / "payload.bin", b"")
            else:
                attempt = InventoryAttempt.from_staged(scope, execution_id, staged)
                _save_payload(directory / "payload.bin", staged, cancelled)
        metadata = dict(
            version=1,
            scope=asdict(scope),
            execution_id=execution_id,
            binding=asdict(binding),
            device_attempt_id=device_attempt_id,
            started_at=attempt.started_at.isoformat(),
            finished_at=attempt.finished_at.isoformat(),
            outcome=attempt.outcome,
            complete=attempt.complete,
            error_code=attempt.error_code,
            payload_fingerprint=attempt.input_fingerprint,
        )
        _write(
            directory / "receipt.json", json.dumps(metadata, sort_keys=True).encode()
        )
        _sync_directory(directory)

    metadata = json.loads(
        _read(directory / "receipt.json", 131072), object_pairs_hook=_unique
    )
    if (
        not isinstance(metadata, dict)
        or set(metadata)
        != {
            "version",
            "scope",
            "execution_id",
            "binding",
            "device_attempt_id",
            "started_at",
            "finished_at",
            "outcome",
            "complete",
            "error_code",
            "payload_fingerprint",
        }
        or type(metadata["version"]) is not int
        or metadata["version"] != 1
    ):
        raise ValueError("Unsupported inventory bundle receipt")
    if (
        metadata["scope"] != asdict(scope)
        or metadata["execution_id"] != execution_id
        or metadata["binding"] != asdict(binding)
        or metadata["device_attempt_id"] != device_attempt_id
    ):
        raise ValueError("Inventory bundle scope or device prerequisite changed")
    attempt = InventoryAttempt(
        scope,
        execution_id,
        datetime.fromisoformat(metadata["started_at"]),
        datetime.fromisoformat(metadata["finished_at"]),
        metadata["payload_fingerprint"],
        metadata["outcome"],
        metadata["complete"],
        metadata["error_code"],
    )
    with _payload(directory / "payload.bin") as source:
        if not attempt.complete:
            if source.read(1) or attempt.input_fingerprint != EMPTY_HASH:
                raise ValueError("Failed inventory bundle cannot contain observations")
            yield attempt, None
        else:
            with stage(source, binding, cancelled=cancelled) as staged:
                if InventoryAttempt.from_staged(scope, execution_id, staged) != attempt:
                    raise ValueError("Inventory saved payload differs from its receipt")
                yield attempt, staged
