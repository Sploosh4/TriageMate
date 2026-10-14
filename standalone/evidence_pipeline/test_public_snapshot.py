"""Public attempts keep common replay semantics without inventing tenants."""

from dataclasses import replace
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from standalone.evidence_pipeline.parsing.public_snapshot import PublicSnapshot
from standalone.evidence_pipeline.persistence.store import (
    atomic,
    stage_attempt,
    ReplayConflict,
)
from .test_public_inputs import scope, epss
from .test_store import db  # noqa: F401


def attempt(payload=None, complete=True):
    now = datetime(2026, 9, 12, tzinfo=timezone.utc)
    return PublicSnapshot(
        scope("FIRST"),
        str(uuid4()),
        now,
        now,
        "success" if complete else "failure",
        complete,
        payload if payload is not None else epss(),
        None if complete else "invalid_public_input",
    )


def test_csv_attempt_keeps_wire_fingerprint():
    value = attempt()
    assert len(value.records()) == 1
    assert value.input_fingerprint == value.feed().input_fingerprint


def test_invalid_public_response_can_only_be_recorded_as_failure():
    with pytest.raises(ValueError):
        attempt(b"not csv")
    failure = attempt(b"not csv", complete=False)
    with pytest.raises(ValueError, match="no complete"):
        failure.feed()


def test_public_registration_and_attempt_replay_without_microsoft_tenant(db):  # noqa: F811
    value = attempt()
    with db.cursor() as cursor, atomic(cursor):
        cursor.execute("SELECT count(*) FROM evidence.microsoft_tenants")
        before = cursor.fetchone()[0]
        assert stage_attempt(cursor, value) is False
        assert stage_attempt(cursor, value) is True
        changed = replace(
            value, payload=value.payload.replace(b"synthetic-v1", b"synthetic-v2")
        )
        with pytest.raises(ReplayConflict):
            stage_attempt(cursor, changed)
        cursor.execute(
            "SELECT tenant_id FROM evidence.source_connections WHERE id=%s",
            (value.scope.connection_id,),
        )
        assert cursor.fetchone() == (None,)
        cursor.execute("SELECT count(*) FROM evidence.microsoft_tenants")
        assert cursor.fetchone()[0] == before


def test_wrong_input_kind_rejected_even_for_failed_attempt():
    value = attempt()
    with pytest.raises(ValueError, match="supported non-tenant"):
        replace(value, scope=replace(value.scope, input_kind="devices"))
