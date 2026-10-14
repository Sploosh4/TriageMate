"""Immutable, owner-only GitHub discovery object bundles for offline continuation."""

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat

from standalone.evidence_pipeline.parsing.github_discovery import (
    current_commit,
    decode,
    object_id,
    object_url,
)
from standalone.evidence_pipeline.collection.osv_query_collection import _read, _sync
from standalone.evidence_pipeline.collection.public_collection import _write
from standalone.evidence_pipeline.collection.public_transport import (
    PublicHTTPError,
    download_github_object,
)


@dataclass(frozen=True)
class ObjectCollection:
    kind: str
    identity: str
    origin: str
    payload: bytes
    error_code: str | None
    started_at: datetime
    finished_at: datetime

    @property
    def complete(self):
        return self.error_code is None


def _url(source, kind, identity):
    if source == "WA SOC":
        from standalone.evidence_pipeline.parsing.wasoc_discovery import (
            object_url as wasoc_object_url,
        )

        return wasoc_object_url(kind, identity)
    if source == "GitHub":
        return object_url(kind, identity)
    if source == "Ubuntu":
        from standalone.evidence_pipeline.parsing.ubuntu_discovery import (
            object_url as ubuntu_object_url,
        )

        return ubuntu_object_url(kind, identity)
    from standalone.evidence_pipeline.parsing.cve_discovery import (
        object_url as cve_object_url,
    )

    return cve_object_url(source, kind, identity)


def validate(kind, identity, payload, *, source="GitHub"):
    _url(source, kind, identity)
    if kind == "ref":
        if source in {"GitHub", "Ubuntu", "WA SOC"}:
            current_commit(payload)
        else:
            from standalone.evidence_pipeline.parsing.cve_discovery import (
                current_commit as cve_current_commit,
            )

            cve_current_commit(source, payload)
        return
    document = decode(payload)
    if document.get("sha") != identity:
        raise ValueError("GitHub object response identity mismatch")
    if kind == "commits":
        tree = document.get("tree")
        if not isinstance(tree, dict):
            raise ValueError("GitHub commit requires a tree")
        object_id(tree.get("sha"))
    elif document.get("truncated") is not False or not isinstance(
        document.get("tree"), list
    ):
        raise ValueError("GitHub discovery tree is incomplete")


def prepare(
    kind,
    identity,
    bundle,
    *,
    origin,
    synthetic_payload=None,
    allow_network=False,
    replay_only=False,
    source="GitHub",
):
    from standalone.evidence_pipeline.collection.collection_scope import (
        require_active_collection,
    )

    require_active_collection(source)
    _url(source, kind, identity)
    options = dict(
        source=source,
        origin=origin,
        synthetic_payload=synthetic_payload,
        allow_network=allow_network,
        replay_only=replay_only,
    )
    if (
        origin == "public"
        and allow_network is True
        and replay_only is False
        and synthetic_payload is None
        and not Path(bundle).exists()
    ):
        from standalone.evidence_pipeline.collection.public_pacing import paced

        # Acquire before creating a receipt directory. A busy source is pending,
        # not an interrupted download; the nested transport reuses this slot.
        with paced("GitHub REST"):
            return _prepare(kind, identity, bundle, **options)
    return _prepare(kind, identity, bundle, **options)


def _prepare(
    kind,
    identity,
    bundle,
    *,
    origin,
    synthetic_payload=None,
    allow_network=False,
    replay_only=False,
    source="GitHub",
):
    url = _url(source, kind, identity)
    if (
        origin not in {"synthetic", "public"}
        or type(allow_network) is not bool
        or type(replay_only) is not bool
    ):
        raise ValueError("Explicit public or synthetic discovery origin required")
    if synthetic_payload is not None and (
        origin != "synthetic" or not isinstance(synthetic_payload, bytes)
    ):
        raise ValueError("Synthetic discovery requires bounded synthetic bytes")
    if allow_network and (origin != "public" or replay_only):
        raise ValueError("Network flag conflicts with discovery mode")
    request = dict(kind=kind, identity=identity, origin=origin, url=url)
    bundle = Path(bundle)
    if bundle.is_symlink():
        raise ValueError("Discovery bundle cannot be a symlink")
    if not bundle.exists():
        if replay_only:
            raise ValueError("Discovery replay bundle does not exist")
        if origin == "public" and not allow_network:
            raise ValueError("Public discovery requires explicit network permission")
        if origin == "synthetic" and synthetic_payload is None:
            raise ValueError("Synthetic discovery requires fixture bytes")
        bundle.mkdir(mode=0o700)
        _sync(bundle.parent)
        _write(bundle / "request.json", json.dumps(request, sort_keys=True).encode())
        _sync(bundle)
        started = datetime.now(timezone.utc)
        payload = b""
        error = None
        try:
            if origin == "synthetic":
                payload = synthetic_payload
            else:
                response = (
                    download_github_object(kind, identity)
                    if source == "GitHub"
                    else download_github_object(kind, identity, source=source)
                )
                if response.url != url or response.wire != response.payload:
                    raise ValueError("Discovery transport changed the requested object")
                payload = response.wire
            _write(bundle / "wire.bin", payload)
            try:
                validate(kind, identity, payload, source=source)
            except (ValueError, UnicodeError):
                error = "invalid_github_discovery_payload"
        except ValueError as exc:
            error = (
                exc.code
                if isinstance(exc, PublicHTTPError)
                else "public_transport_failed"
            )
        receipt = dict(
            request,
            started_at=started.isoformat(),
            finished_at=datetime.now(timezone.utc).isoformat(),
            error_code=error,
            fingerprint=hashlib.sha256(payload).hexdigest(),
            has_wire=(bundle / "wire.bin").exists(),
        )
        _write(bundle / "receipt.json", json.dumps(receipt, sort_keys=True).encode())
        _sync(bundle)
    info = bundle.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_mode & 0o077
        or info.st_uid != os.getuid()
    ):
        raise ValueError("Discovery bundle must be an owner-only directory")
    try:
        original = decode(_read(bundle / "request.json", 4096))
        receipt = decode(_read(bundle / "receipt.json", 8192))
        if original != request or any(
            receipt.get(key) != value for key, value in request.items()
        ):
            raise ValueError("Discovery bundle belongs to a different object or origin")
        if type(receipt.get("has_wire")) is not bool:
            raise ValueError("Invalid discovery receipt")
        payload = _read(bundle / "wire.bin") if receipt["has_wire"] else b""
    except FileNotFoundError as exc:
        raise ValueError(
            "Interrupted discovery bundle requires investigation; no refetch"
        ) from exc
    if receipt.get("fingerprint") != hashlib.sha256(payload).hexdigest():
        raise ValueError("Discovery response fingerprint changed")
    if synthetic_payload is not None and synthetic_payload != payload:
        raise ValueError("Synthetic discovery replay changed fixture bytes")
    started = datetime.fromisoformat(receipt["started_at"])
    finished = datetime.fromisoformat(receipt["finished_at"])
    if (
        started.utcoffset() is None
        or finished.utcoffset() is None
        or finished < started
    ):
        raise ValueError("Invalid discovery receipt timestamps")
    error = receipt.get("error_code")
    allowed = {
        None,
        "invalid_github_discovery_payload",
        "public_transport_failed",
        "public_not_found",
        "public_gone",
        "public_access_denied",
        "public_rate_limited",
        "public_unavailable",
        "public_http_failed",
    }
    if error not in allowed:
        raise ValueError("Invalid discovery outcome")
    if error is None:
        validate(kind, identity, payload, source=source)
    return ObjectCollection(kind, identity, origin, payload, error, started, finished)
