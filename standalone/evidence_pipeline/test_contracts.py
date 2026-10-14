from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from uuid import uuid4

import pytest

from standalone.evidence_pipeline.contracts import SourceScope, Snapshot, select_current


@pytest.fixture
def snapshot():
    now = datetime(2026, 9, 12, tzinfo=timezone.utc)
    scope = SourceScope(
        str(uuid4()),
        "Entra",
        "devices",
        "fixture",
        "synthetic",
        "generated test",
        str(uuid4()),
    )
    return Snapshot(
        scope,
        str(uuid4()),
        now,
        now + timedelta(seconds=1),
        "success",
        True,
        b'[{"id":"fixture","enabled":false,"count":0,"unknown":null}]',
    )


def test_false_zero_unknown_and_input_identity(snapshot):
    assert snapshot.records()[0] == {
        "id": "fixture",
        "enabled": False,
        "count": 0,
        "unknown": None,
    }
    assert (
        replace(snapshot, payload=b" " + snapshot.payload).input_fingerprint
        != snapshot.input_fingerprint
    )
    result = snapshot.records()
    result[0]["id"] = "changed"
    assert snapshot.records()[0]["id"] == "fixture"


@pytest.mark.parametrize(
    "payload",
    [b"[NaN]", b'[{"x":1,"x":2}]', b"{}", b"[1]", b"\xff", b'[{"x":Infinity}]'],
)
def test_rejects_ambiguous_or_invalid_wire_data(snapshot, payload):
    with pytest.raises(ValueError):
        replace(snapshot, payload=payload)


@pytest.mark.parametrize(
    "changes",
    [
        {"outcome": "failure"},
        {"complete": False},
        {"complete": 1},
        {"started_at": datetime(2026, 9, 12)},
        {"error_code": "raw secret message"},
        {"execution_id": "00000000-0000-0000-0000-000000000000"},
        {"finished_at": datetime(2025, 1, 1, tzinfo=timezone.utc)},
    ],
)
def test_rejects_invalid_attempts(snapshot, changes):
    with pytest.raises(ValueError):
        replace(snapshot, **changes)


def test_failed_and_partial_snapshots_do_not_replace_success(snapshot):
    later = snapshot.finished_at + timedelta(days=1)
    failed = replace(
        snapshot,
        execution_id=str(uuid4()),
        finished_at=later,
        outcome="failure",
        complete=False,
        payload=b"[]",
        error_code="unavailable",
    )
    partial = replace(failed, execution_id=str(uuid4()), outcome="partial")
    assert select_current([snapshot, failed, partial], snapshot.scope) == snapshot
    assert select_current([failed, partial], snapshot.scope) is None


def test_complete_empty_snapshot_is_not_failure(snapshot):
    empty = replace(
        snapshot,
        execution_id=str(uuid4()),
        finished_at=snapshot.finished_at + timedelta(seconds=1),
        payload=b"[]",
    )
    assert select_current([empty, snapshot], snapshot.scope) == empty


def test_other_connections_and_scope_metadata_never_mix(snapshot):
    for change in (
        {"connection_id": str(uuid4())},
        {"tenant_id": str(uuid4())},
        {"scope_reference": "other"},
    ):
        other = replace(snapshot, scope=replace(snapshot.scope, **change))
        assert select_current([other], snapshot.scope) is None


def test_microsoft_sources_require_tenant_and_nonpublic_origin(snapshot):
    for changes in ({"tenant_id": None}, {"origin": "public"}, {"origin": "customer"}):
        with pytest.raises(ValueError):
            replace(snapshot.scope, **changes)


def test_record_count_limit(snapshot, monkeypatch):
    monkeypatch.setattr("standalone.evidence_pipeline.contracts.MAX_RECORDS", 1)
    with pytest.raises(ValueError):
        replace(snapshot, payload=json.dumps([{}, {}]).encode())


def test_decimal_values_remain_exact(snapshot):
    from decimal import Decimal

    precise = replace(
        snapshot, payload=b'[{"probability":0.12345678901234567890123456789}]'
    )
    assert precise.records()[0]["probability"] == Decimal(
        "0.12345678901234567890123456789"
    )


def test_failed_response_can_be_fingerprinted_without_parsing(snapshot):
    import hashlib

    failed = replace(
        snapshot, complete=False, outcome="failure", payload=b"\xfffailure"
    )
    assert failed.input_fingerprint == hashlib.sha256(b"\xfffailure").hexdigest()
    assert select_current([failed], snapshot.scope) is None
    with pytest.raises(ValueError):
        failed.records()
