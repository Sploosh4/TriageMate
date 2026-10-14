"""Owner-only durable Microsoft snapshot retries, independent of database commits.

Payloads are the collected record array, not the original HTTP page bytes.
An existing incomplete bundle is an error: it never triggers another collection.
"""

from dataclasses import asdict
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import stat

from standalone.evidence_pipeline.contracts import Snapshot, identifier


def _sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _private_directory(path):
    info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_mode & 0o077
        or info.st_uid != os.getuid()
    ):
        raise ValueError("Snapshot storage must be an owner-only directory")


def _write(path, data):
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def _read(path, limit=None):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_mode & 0o077
            or info.st_uid != os.getuid()
            or (limit is not None and info.st_size > limit)
        ):
            raise ValueError("Invalid snapshot bundle file")
        data = stream.read() if limit is None else stream.read(limit + 1)
    if limit is not None and len(data) > limit:
        raise ValueError("Oversized snapshot bundle file")
    return data


def prepare(scope, execution_id, root, *, collect, binding=None):
    """Call collect once, durably save its snapshot, or replay that exact snapshot.

    The caller supplies a private local storage root outside tracked source files.
    Credentials and raw exceptions must not be included in the returned snapshot.
    A collection exception leaves an incomplete bundle requiring operator review.
    Database ingestion happens only after this function returns.
    """
    return _prepare(scope, execution_id, root, collect=collect, binding=binding)


def prepare_with_associations(scope, execution_id, root, *, collect, binding):
    """Save/replay a software snapshot and exact association bytes as one receipt.

    The callback returns (Snapshot, bytes), or (failed Snapshot, None). No DB
    import may occur until this returns. An interrupted write never refetches.
    The explicit device binding is required even for an empty application list.
    """
    if scope.source != "Intune" or scope.input_kind != "software" or not binding:
        raise ValueError("Associated bundles require bound Intune software evidence")
    return _prepare(
        scope, execution_id, root, collect=collect, binding=binding, associated=True
    )


def prepare_recommendations(scope, execution_id, root, *, collect, binding):
    """Save recommendation records and exact device associations together."""
    if (
        scope.source != "Defender"
        or scope.input_kind != "recommendations"
        or not binding
    ):
        raise ValueError("Recommendation bundles require bound Defender advice")
    return _prepare(
        scope, execution_id, root, collect=collect, binding=binding, associated=True
    )


def _prepare(scope, execution_id, root, *, collect, binding, associated=False):
    if binding is not None:
        if (
            not isinstance(binding, dict)
            or not 1 <= len(binding) <= 8
            or any(
                not isinstance(key, str)
                or not 1 <= len(key) <= 128
                or not isinstance(value, str)
                or len(value) > 4096
                for key, value in binding.items()
            )
        ):
            raise ValueError("Invalid snapshot binding")
        binding = dict(binding)
        if len(json.dumps(binding).encode()) > 8192:
            raise ValueError("Oversized snapshot binding")
    version = 3 if associated else (2 if binding is not None else 1)
    execution_id = identifier(execution_id)
    if scope.source not in ("Entra", "Intune", "Defender"):
        raise ValueError("Microsoft snapshot storage requires a Microsoft scope")
    root = Path(root).absolute()
    if root.resolve() != root:
        raise ValueError("Snapshot storage cannot traverse symlinks")
    _private_directory(root)
    bundle = root / execution_id
    try:
        bundle.mkdir(mode=0o700)
    except FileExistsError:
        _private_directory(bundle)
    else:
        _sync_directory(root)
        collected = collect()
        snapshot, relations = collected if associated else (collected, None)
        if (
            not isinstance(snapshot, Snapshot)
            or snapshot.scope != scope
            or snapshot.execution_id != execution_id
        ):
            raise ValueError(
                "Collection returned a different snapshot scope or execution"
            )
        metadata = dict(
            version=version,
            scope=asdict(scope),
            execution_id=execution_id,
            started_at=snapshot.started_at.isoformat(),
            finished_at=snapshot.finished_at.isoformat(),
            outcome=snapshot.outcome,
            complete=snapshot.complete,
            error_code=snapshot.error_code,
            payload_fingerprint=snapshot.input_fingerprint,
        )
        if binding is not None:
            metadata["binding"] = binding
        if associated:
            _validate_associations(snapshot, relations)
            metadata["association_fingerprint"] = (
                hashlib.sha256(relations).hexdigest() if relations is not None else None
            )
            if relations is not None:
                _write(bundle / "associations.bin", relations)
        _write(bundle / "payload.bin", snapshot.payload)
        _write(bundle / "receipt.json", json.dumps(metadata, sort_keys=True).encode())
        _sync_directory(bundle)

    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate snapshot receipt field")
            value[key] = item
        return value

    metadata = json.loads(
        _read(bundle / "receipt.json", 131072), object_pairs_hook=unique
    )
    fields = {
        "version",
        "scope",
        "execution_id",
        "started_at",
        "finished_at",
        "outcome",
        "complete",
        "error_code",
        "payload_fingerprint",
    }
    if binding is not None:
        fields.add("binding")
    if associated:
        fields.add("association_fingerprint")
    if not isinstance(metadata, dict) or set(metadata) != fields:
        raise ValueError("Invalid snapshot receipt")
    if binding is not None and metadata["binding"] != binding:
        raise ValueError("Snapshot device binding differs from its receipt")
    if (
        type(metadata["version"]) is not int
        or metadata["version"] != version
        or metadata["scope"] != asdict(scope)
        or metadata["execution_id"] != execution_id
    ):
        raise ValueError("Snapshot receipt belongs to a different scope or version")
    payload = _read(bundle / "payload.bin")
    if hashlib.sha256(payload).hexdigest() != metadata["payload_fingerprint"]:
        raise ValueError("Snapshot payload differs from its receipt")
    snapshot = Snapshot(
        scope,
        execution_id,
        datetime.fromisoformat(metadata["started_at"]),
        datetime.fromisoformat(metadata["finished_at"]),
        metadata["outcome"],
        metadata["complete"],
        payload,
        metadata["error_code"],
    )
    if not associated:
        return snapshot
    fingerprint = metadata["association_fingerprint"]
    relations = _read(bundle / "associations.bin") if fingerprint is not None else None
    if relations is not None and hashlib.sha256(relations).hexdigest() != fingerprint:
        raise ValueError("Association payload differs from its receipt")
    _validate_associations(snapshot, relations)
    return snapshot, relations


def _validate_associations(snapshot, relations):
    if not snapshot.complete:
        if relations is not None:
            raise ValueError("Incomplete collection cannot retain associations")
        return
    from standalone.evidence_pipeline.parsing.exposure import associations

    associations(relations)
