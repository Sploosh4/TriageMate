"""PostgreSQL timestamp formatting must not look like altered source evidence."""

from datetime import datetime, timedelta
from uuid import uuid4

import pytest

from standalone.evidence_pipeline.persistence.attribution import (
    digest,
    retained_device_fields,
)
from standalone.evidence_pipeline.parsing.devices import TIME_FIELDS, normalize_devices
from .test_completeness import put
from .test_devices import make
from .test_store import db as db


@pytest.mark.parametrize(
    "source,field",
    [
        ("Entra", "registrationDateTime"),
        ("Intune", "lastSyncDateTime"),
        ("Defender", "lastSeen"),
    ],
)
@pytest.mark.parametrize(
    "value",
    [
        "2026-09-17T16:00:00.100000Z",
        "2026-09-18T00:00:00.123400+08:00",
        "2026-09-17T16:00:00Z",
    ],
)
def test_database_timestamp_roundtrip_preserves_hash_and_detects_tampering(
    db, source, field, value
):
    raw = {"id": str(uuid4()), field: value}
    snapshot = make(source, [raw])
    device = normalize_devices(snapshot)[0]
    put(db, snapshot)
    with db.cursor() as cur:
        cur.execute("RESET ROLE")
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        cur.execute(
            "SELECT to_jsonb(o),r.content_hash FROM evidence.device_observations o JOIN evidence.observation_receipts rc ON rc.id=o.receipt_id JOIN evidence.source_revisions r ON r.id=rc.source_revision_id WHERE rc.collection_attempt_id=%s",
            (snapshot.execution_id,),
        )
        observation, stored = cur.fetchone()
    fields = retained_device_fields(source, observation)

    def hashed(values):
        return digest(
            [
                source,
                device.native_id,
                device.registration_id,
                device.identity_issue,
                values,
            ]
        )

    assert hashed(fields) == stored == device.content_hash
    target = next(key for key, wire in TIME_FIELDS[source].items() if wire == field)
    damaged = dict(observation)
    damaged[target] = (
        datetime.fromisoformat(fields[target]) + timedelta(microseconds=1)
    ).isoformat()
    assert hashed(retained_device_fields(source, damaged)) != stored
