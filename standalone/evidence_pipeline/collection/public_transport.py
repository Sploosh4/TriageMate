"""Bounded anonymous HTTPS transport for the approved public evidence sources.

No credentials, arbitrary URLs, cross-host redirects, environment proxies or retries. The
caller owns scheduling and records failures; this module never changes a database.
"""

from datetime import datetime, timezone
import gzip
import hashlib
import http.client
import io
import os
from pathlib import Path

from standalone.evidence_pipeline.file_payload import FilePayload
from standalone.evidence_pipeline.contracts import PublicDownload
import re
import time
import zlib
from urllib.parse import urlsplit

from standalone.evidence_pipeline.parsing.public_routes import endpoint


class PublicHTTPError(ValueError):
    """Safe source outcome; never retain response bodies or authentication details."""

    def __init__(self, status):
        self.code = {
            404: "public_not_found",
            410: "public_gone",
            401: "public_access_denied",
            403: "public_access_denied",
            429: "public_rate_limited",
        }.get(
            status,
            "public_unavailable" if 500 <= status <= 599 else "public_http_failed",
        )
        super().__init__(f"Public source returned HTTP {status}")


def download_vendor(scope, *, save_to=None):
    """Anonymous bounded download after exact vendor route/origin validation."""
    from standalone.evidence_pipeline.collection.collection_scope import (
        require_active_collection,
    )

    require_active_collection(scope.source)
    from standalone.evidence_pipeline.parsing.advisory_feeds import validate_scope

    validate_scope(scope)
    if scope.origin != "public":
        raise ValueError("Synthetic vendor evidence must never use the network")
    return _download_url(scope.scope_reference, save_to=save_to)


def download(
    source: str,
    *,
    cve: str | None = None,
    month: str | None = None,
    score_date: str | None = None,
    input_kind: str | None = None,
    advisory_id: str | None = None,
    repository_commit: str | None = None,
    repository_path: str | None = None,
    vendor_path: str | None = None,
    save_to=None,
) -> PublicDownload:
    """Fetch a complete response with 30s socket timeouts.

    A 60s elapsed budget is checked between reads; an in-flight socket operation can
    last up to its 30s timeout. DNS resolution follows the operating system timeout.
    No download byte cap applies. Content-Length and gzip CRC are verified.
    """
    from standalone.evidence_pipeline.collection.collection_scope import (
        require_active_collection,
    )

    require_active_collection(source, score_date=score_date)
    url = endpoint(
        source,
        cve,
        month=month,
        score_date=score_date,
        input_kind=input_kind,
        advisory_id=advisory_id,
        repository_commit=repository_commit,
        repository_path=repository_path,
        vendor_path=vendor_path,
    )
    return _download_url(
        url,
        first=source == "FIRST",
        save_to=save_to,
    )


def download_github_object(kind, identity, *, source="GitHub"):
    """Read one pinned advisory-repository object; never retry or follow redirects.

    A database-shared 61-second slot spaces fresh REST calls. The caller owns
    durable caching; unrelated tools sharing the public IP remain outside this lock.
    """
    from standalone.evidence_pipeline.collection.collection_scope import (
        require_active_collection,
    )

    require_active_collection(source)
    from standalone.evidence_pipeline.parsing.github_discovery import object_url

    from standalone.evidence_pipeline.collection.public_pacing import paced

    if source == "GitHub":
        url = object_url(kind, identity)
    elif source == "WA SOC":
        from standalone.evidence_pipeline.parsing.wasoc_discovery import (
            object_url as wasoc_object_url,
        )

        url = wasoc_object_url(kind, identity)
    elif source == "Ubuntu":
        from standalone.evidence_pipeline.parsing.ubuntu_discovery import (
            object_url as ubuntu_object_url,
        )

        url = ubuntu_object_url(kind, identity)
    else:
        from standalone.evidence_pipeline.parsing.cve_discovery import (
            object_url as cve_object_url,
        )

        url = cve_object_url(source, kind, identity)
    with paced("GitHub REST"):
        return _download_url(url, github_api=True)


def read_complete(
    stream, *, deadline, connection=None, cancelled=lambda: False, output=None
):
    """Check the elapsed budget between single buffered reads, including decoding.

    BytesIO avoids the second whole-response copy made by joining retained chunks.
    This still materializes the response; it is not a bounded-memory importer.
    """
    owned = output is None
    output = io.BytesIO() if owned else output
    total = 0
    try:
        while True:
            if cancelled():
                raise ValueError("Public download cancelled")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError("Public download elapsed budget exceeded")
            sock = getattr(connection, "sock", None)
            if sock is not None:
                sock.settimeout(min(30, remaining))
            # read1 avoids waiting to fill a 64 KiB block under a trickling peer.
            chunk = stream.read1(65536)
            if not chunk:
                if cancelled():
                    raise ValueError("Public download cancelled")
                if time.monotonic() >= deadline:
                    raise ValueError("Public download elapsed budget exceeded")
                return output.getvalue() if owned else total
            output.write(chunk)
            total += len(chunk)
    finally:
        if owned:
            output.close()


def _decode_gzip_file(wire, path, *, deadline, cancelled):
    """Decode into an owned file, removing only our failed decoded output."""
    created = complete = False
    try:
        with path.open("xb") as output:
            created = True
            os.chmod(path, 0o600)
            with wire.open(cancelled=cancelled) as saved:
                with gzip.GzipFile(fileobj=saved) as stream:
                    length = read_complete(
                        stream, deadline=deadline, cancelled=cancelled, output=output
                    )
            output.flush()
            os.fsync(output.fileno())
        if not length:
            raise ValueError("Decoded public response is empty")
        with path.open("rb") as saved:
            fingerprint = hashlib.file_digest(saved, "sha256").hexdigest()
        if cancelled() or time.monotonic() >= deadline:
            raise ValueError("Public download cancelled or elapsed budget exceeded")
        result = FilePayload(path.resolve(), fingerprint)
        complete = True
        return result
    finally:
        if created and not complete:
            path.unlink()


def _download_url(
    url, *, first=False, github_api=False, cancelled=lambda: False, save_to=None
):
    """Internal transport; callers construct and validate fixed publisher routes."""
    target = urlsplit(url)
    started = datetime.now(timezone.utc)
    deadline = time.monotonic() + 60
    connection = http.client.HTTPSConnection(target.hostname, timeout=30)
    try:
        path = target.path + ("?" + target.query if target.query else "")
        connection.request(
            "GET",
            path,
            headers={
                "Accept-Encoding": "identity",
                "User-Agent": "TriageMate-evidence/1.0",
                "Accept": "application/vnd.github+json"
                if github_api
                else "application/json,text/csv,application/gzip,application/octet-stream",
                **({"X-GitHub-Api-Version": "2026-03-10"} if github_api else {}),
            },
        )
        response = connection.getresponse()
        if first and response.status in (301, 302, 307, 308):
            location = response.getheader("Location", "")
            if not re.fullmatch(
                r"epss_scores-[0-9]{4}-[0-9]{2}-[0-9]{2}\.csv\.gz", location
            ):
                raise ValueError("Unapproved public redirect")
            # FIRST current points to one dated file on the same publisher host.
            connection.close()
            connection = http.client.HTTPSConnection(target.hostname, timeout=30)
            connection.request(
                "GET",
                "/" + location,
                headers={
                    "Accept-Encoding": "identity",
                    "User-Agent": "TriageMate-evidence/1.0",
                },
            )
            response = connection.getresponse()
            url = "https://" + target.hostname + "/" + location
        if response.status != 200:
            raise PublicHTTPError(response.status)
        if response.getheader("Content-Encoding", "identity").lower() not in (
            "identity",
            "",
        ):
            raise ValueError("Unexpected HTTP content encoding")
        length = response.getheader("Content-Length")
        if length is not None and not length.isdecimal():
            raise ValueError("Invalid public response length")
        if save_to is None:
            wire = read_complete(
                response, deadline=deadline, connection=connection, cancelled=cancelled
            )
            wire_length = len(wire)
        else:
            path = Path(save_to)
            with path.open("xb") as output:
                os.chmod(path, 0o600)
                wire_length = read_complete(
                    response,
                    deadline=deadline,
                    connection=connection,
                    cancelled=cancelled,
                    output=output,
                )
                output.flush()
                os.fsync(output.fileno())
            with path.open("rb") as saved:
                fingerprint = hashlib.file_digest(saved, "sha256").hexdigest()
            if cancelled() or time.monotonic() >= deadline:
                raise ValueError("Public download cancelled or elapsed budget exceeded")
            wire = FilePayload(path.resolve(), fingerprint)
        if not wire_length or (length is not None and wire_length != int(length)):
            raise ValueError("Empty or incomplete public response")
        payload = wire
        if first:
            if isinstance(wire, FilePayload):
                payload = _decode_gzip_file(
                    wire,
                    wire.path.parent / "payload.bin",
                    deadline=deadline,
                    cancelled=cancelled,
                )
            else:
                with gzip.GzipFile(fileobj=io.BytesIO(wire)) as stream:
                    payload = read_complete(
                        stream, deadline=deadline, cancelled=cancelled
                    )
                if not payload:
                    raise ValueError("Decoded public response is empty")
        return PublicDownload(url, started, datetime.now(timezone.utc), wire, payload)
    except (OSError, http.client.HTTPException, EOFError, zlib.error) as exc:
        raise ValueError(
            "Public source transport failed; no complete input available"
        ) from exc
    finally:
        connection.close()
