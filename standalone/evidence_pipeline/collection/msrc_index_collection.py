"""Immutable streamed MSRC index receipts; replay never makes a network request."""

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import time

from standalone.evidence_pipeline.contracts import identifier, utc
from standalone.evidence_pipeline.file_payload import FilePayload
from standalone.evidence_pipeline.parsing.msrc_publications import (
    INDEX_URL,
    publications,
)
from standalone.evidence_pipeline.collection.osv_query_collection import _read, _sync
from standalone.evidence_pipeline.collection.public_collection import _write
from standalone.evidence_pipeline.collection.public_transport import (
    PublicHTTPError,
    _download_url,
)
from standalone.evidence_pipeline.collection.snapshot_bundle import _private_directory

ERRORS = {
    None,
    "invalid_msrc_index",
    "public_transport_failed",
    "public_cancelled",
    "public_not_found",
    "public_gone",
    "public_access_denied",
    "public_rate_limited",
    "public_unavailable",
    "public_http_failed",
}


@dataclass(frozen=True)
class IndexSnapshot:
    origin: str
    execution_id: str
    started_at: datetime
    finished_at: datetime
    payload: FilePayload | None
    error_code: str | None

    @property
    def complete(self):
        return self.error_code is None

    def items(self, *, cancelled=lambda: False):
        if not self.complete:
            raise ValueError("Failed MSRC index cannot select publications")
        with self.payload.open(cancelled=cancelled) as stream:
            yield from publications(stream, cancelled=cancelled)


def prepare(
    bundle,
    execution_id,
    *,
    origin,
    allow_network=False,
    replay_only=False,
    synthetic_payload=None,
    cancelled=lambda: False,
):
    execution_id = identifier(execution_id)
    if (
        origin not in {"synthetic", "public"}
        or type(allow_network) is not bool
        or type(replay_only) is not bool
        or (allow_network and (origin != "public" or replay_only))
        or (
            synthetic_payload is not None
            and (origin != "synthetic" or not isinstance(synthetic_payload, bytes))
        )
    ):
        raise ValueError("Invalid MSRC index authority")
    root = Path(bundle)
    if root.is_symlink():
        raise ValueError("MSRC index bundle cannot be a symlink")
    request = dict(origin=origin, execution_id=execution_id, source_url=INDEX_URL)
    deadline = time.monotonic() + 60

    def stopped():
        return cancelled() or time.monotonic() >= deadline

    if not root.exists():
        if (
            replay_only
            or (origin == "public" and not allow_network)
            or (origin == "synthetic" and synthetic_payload is None)
        ):
            raise ValueError("Fresh MSRC index requires explicit input authority")
        root.mkdir(mode=0o700)
        _sync(root.parent)
        _write(root / "request.json", json.dumps(request, sort_keys=True).encode())
        _sync(root)
        started = datetime.now(timezone.utc)
        payload, error = None, None
        path = root / "wire.bin"
        try:
            if stopped():
                raise ValueError("MSRC index cancelled")
            if origin == "synthetic":
                _write(path, synthetic_payload)
                payload = FilePayload(
                    path.resolve(), hashlib.sha256(synthetic_payload).hexdigest()
                )
            else:
                response = _download_url(INDEX_URL, save_to=path, cancelled=stopped)
                if (
                    response.url != INDEX_URL
                    or response.wire != response.payload
                    or not isinstance(response.payload, FilePayload)
                    or response.payload.path != path.resolve()
                ):
                    raise ValueError("MSRC index transport changed source or bytes")
                payload = response.payload
        except BaseException as exc:
            # Only this fresh attempt owns this file; incomplete bytes are not evidence.
            if path.exists():
                path.unlink()
            if not isinstance(exc, ValueError):
                raise
            error = (
                "public_cancelled"
                if stopped()
                else (
                    exc.code
                    if isinstance(exc, PublicHTTPError)
                    else "public_transport_failed"
                )
            )
        if payload is not None:
            try:
                with payload.open(cancelled=stopped) as stream:
                    for _ in publications(stream, cancelled=stopped):
                        pass
            except ValueError:
                error = "public_cancelled" if stopped() else "invalid_msrc_index"
        receipt = dict(
            request,
            started_at=started.isoformat(),
            finished_at=datetime.now(timezone.utc).isoformat(),
            fingerprint=payload.fingerprint if payload else None,
            error_code=error,
        )
        _write(root / "receipt.json", json.dumps(receipt, sort_keys=True).encode())
        _sync(root)
    _private_directory(root)
    try:
        original = json.loads(_read(root / "request.json", 4096))
        receipt = json.loads(_read(root / "receipt.json", 8192))
    except FileNotFoundError as exc:
        raise ValueError(
            "Interrupted MSRC index requires investigation; no refetch"
        ) from exc
    expected = {*request, "started_at", "finished_at", "fingerprint", "error_code"}
    if (
        not isinstance(receipt, dict)
        or original != request
        or set(receipt) != expected
        or any(receipt[k] != v for k, v in request.items())
        or receipt["error_code"] not in tuple(ERRORS)
    ):
        raise ValueError("MSRC index receipt differs from request")
    if any(not isinstance(receipt[key], str) for key in ("started_at", "finished_at")):
        raise ValueError("Invalid MSRC index collection dates")
    if (root / "wire.bin").is_symlink():
        raise ValueError("MSRC index payload cannot be a symlink")
    started = utc(datetime.fromisoformat(receipt["started_at"]))
    finished = utc(datetime.fromisoformat(receipt["finished_at"]))
    if finished < started:
        raise ValueError("Invalid MSRC index collection dates")
    payload = None
    if receipt["fingerprint"] is not None:
        payload = FilePayload((root / "wire.bin").resolve(), receipt["fingerprint"])
        with payload.open(cancelled=stopped) as stream:
            if receipt["error_code"] is None:
                for _ in publications(stream, cancelled=stopped):
                    pass
        if (
            synthetic_payload is not None
            and hashlib.sha256(synthetic_payload).hexdigest() != payload.fingerprint
        ):
            raise ValueError("Synthetic index differs from saved bytes")
    elif receipt["error_code"] is None or (root / "wire.bin").exists():
        raise ValueError("MSRC index payload does not match outcome")
    return IndexSnapshot(
        origin, execution_id, started, finished, payload, receipt["error_code"]
    )
