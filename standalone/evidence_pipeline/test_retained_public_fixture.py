"""Offline fixtures for retained schema tests; never a runtime collection route."""

from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import hashlib
import json

from .contracts import Snapshot
from standalone.evidence_pipeline.parsing.public_snapshot import PublicSnapshot
from standalone.evidence_pipeline.contracts import PublicDownload
from standalone.evidence_pipeline.parsing.osv_query import (
    URL,
    package_query,
    parse_pages,
)
from standalone.evidence_pipeline.collection.osv_query_collection import QueryCollection


_snapshots = {}
_last_time = datetime.min.replace(tzinfo=timezone.utc)


def _next_time():
    """Keep successive fixture attempts ordered, even at one clock tick."""
    global _last_time
    _last_time = max(datetime.now(timezone.utc), _last_time + timedelta(microseconds=1))
    return _last_time


def prepare(
    scope,
    execution_id,
    bundle,
    *,
    synthetic_payload=None,
    replay_only=False,
    **parameters,
):
    if scope.origin != "synthetic":
        raise ValueError("Retained evidence fixtures require synthetic scope")
    key = str(bundle)
    if replay_only:
        value = _snapshots[key]
        if value.scope != scope or value.execution_id != execution_id:
            raise ValueError("Fixture belongs to a different scope or execution")
        return value
    if not isinstance(synthetic_payload, bytes):
        raise ValueError("Retained evidence fixtures require explicit synthetic bytes")
    now = _next_time()
    try:
        value = PublicSnapshot(
            scope, execution_id, now, now, "success", True, synthetic_payload
        )
    except ValueError:
        value = PublicSnapshot(
            scope,
            execution_id,
            now,
            now,
            "failure",
            False,
            synthetic_payload,
            "invalid_public_payload",
        )
    _snapshots[key] = value
    return value


def query_fixture(scope, execution_id, bundle, *, synthetic_pages=None, **parameters):
    if scope.origin != "synthetic" or not synthetic_pages:
        raise ValueError("Retained query fixtures require explicit synthetic pages")
    query = package_query(**parameters)
    now = _next_time()
    responses = tuple(
        PublicDownload(URL, now, now, raw, raw) for raw in synthetic_pages
    )
    error = None
    try:
        result = parse_pages(scope=scope, query=query, responses=responses)
    except ValueError:
        result = None
        error = "osv_query_failed"
    metadata = dict(
        format="triagemate-osv-query-v1",
        scope=asdict(scope),
        execution_id=execution_id,
        query=query,
        started_at=now.isoformat(),
        finished_at=now.isoformat(),
        error_code=error,
        pages=[
            dict(
                started_at=now.isoformat(),
                finished_at=now.isoformat(),
                fingerprint=hashlib.sha256(r.wire).hexdigest(),
            )
            for r in responses
        ],
    )
    snap = Snapshot(
        scope,
        execution_id,
        now,
        now,
        "failure" if error else "success",
        error is None,
        json.dumps([metadata]).encode(),
        error,
    )
    return QueryCollection(snap, result, responses)
