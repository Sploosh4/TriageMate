"""Current deferred constraints preserve source relationships and exact replay."""

from dataclasses import replace
from uuid import uuid4

import psycopg2
import pytest

from backend.database import schema as database_schema

from standalone.evidence_pipeline.persistence.store import persist_devices, atomic
from .test_store import db as database_fixture, snapshot as snapshot_fixture
from .test_public_snapshot import attempt
from .test_public_inputs import epss
from standalone.evidence_pipeline.persistence.authority import authorize_connection
from standalone.evidence_pipeline.persistence.public_store import persist_public

db = database_fixture
snapshot = snapshot_fixture


@pytest.fixture
def pair(db, snapshot):
    other = replace(
        snapshot,
        execution_id=str(uuid4()),
        scope=replace(snapshot.scope, connection_id=str(uuid4())),
    )
    persist_devices(db, snapshot)
    persist_devices(db, other)
    with db.cursor() as cursor:
        database_schema.verify(cursor)
        cursor.execute(
            "SELECT r.id,r.source_revision_id,r.collection_attempt_id,o.provider_device_id FROM evidence.observation_receipts r JOIN evidence.device_observations o ON o.receipt_id=r.id WHERE r.collection_attempt_id IN (%s,%s) ORDER BY r.collection_attempt_id",
            (snapshot.execution_id, other.execution_id),
        )
        return cursor.fetchall()


@pytest.mark.parametrize(
    "mode",
    [
        "receipt",
        "revision-update",
        "attempt-update",
        "device-child",
        "device-parent-update",
    ],
)
def test_invalid_relationships_still_rejected(db, pair, mode):
    a, b = pair
    with db.cursor() as cursor:
        with (
            pytest.raises(psycopg2.errors.RaiseException, match="connections differ"),
            atomic(cursor),
        ):
            if mode == "receipt":
                cursor.execute(
                    "INSERT INTO evidence.observation_receipts VALUES(%s,%s,%s)",
                    (str(uuid4()), a[1], b[2]),
                )
            elif mode == "revision-update":
                cursor.execute(
                    "UPDATE evidence.source_revisions SET source_record_id=source_record_id||'-changed',connection_id=(SELECT connection_id FROM evidence.source_revisions WHERE id=%s) WHERE id=%s",
                    (b[1], a[1]),
                )
            elif mode == "attempt-update":
                cursor.execute(
                    "UPDATE evidence.collection_attempts SET connection_id=(SELECT connection_id FROM evidence.source_revisions WHERE id=%s) WHERE id=%s",
                    (b[1], a[2]),
                )
            elif mode == "device-child":
                cursor.execute(
                    "INSERT INTO evidence.device_observations(id,provider_device_id,receipt_id) VALUES(%s,%s,%s)",
                    (str(uuid4()), a[3], b[0]),
                )
            else:
                cursor.execute(
                    "UPDATE evidence.provider_devices SET native_device_id=native_device_id||'-changed',connection_id=(SELECT connection_id FROM evidence.source_revisions WHERE id=%s) WHERE id=%s",
                    (b[1], a[3]),
                )
        cursor.execute("SELECT 1")
        assert cursor.fetchone() == (1,)


@pytest.mark.parametrize("valid", [True, False])
def test_receipt_before_revision_validated_at_end(db, pair, valid):
    a, b = pair
    with db.cursor() as cursor:

        def write():
            revision = str(uuid4())
            with atomic(cursor):
                cursor.execute(
                    "INSERT INTO evidence.observation_receipts VALUES(%s,%s,%s)",
                    (str(uuid4()), revision, a[2]),
                )
                cursor.execute(
                    "INSERT INTO evidence.source_revisions SELECT %s,connection_id,source_record_id||'-new',source_updated_at,collected_at,content_hash,origin,source_url,licence_or_provenance FROM evidence.source_revisions WHERE id=%s",
                    (revision, (a if valid else b)[1]),
                )

        if valid:
            write()
        else:
            with pytest.raises(
                psycopg2.errors.RaiseException, match="connections differ"
            ):
                write()


def test_thousand_public_rows_and_replay_remain_exact(db):
    value = attempt(
        epss(
            "".join(
                f"CVE-2099-{9000000 + i},0.123456789012345678901,0.2\n"
                for i in range(1000)
            )
        )
    )
    value = replace(value, scope=replace(value.scope, connection_id=str(uuid4())))
    with db.cursor() as cursor:
        database_schema.verify(cursor)
        authorize_connection(cursor, value)
        cursor.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
    assert not persist_public(db, value)["replayed"]
    assert persist_public(db, value)["replayed"]
    with db.cursor() as cursor:
        cursor.execute(
            "SELECT probability::text FROM evidence.epss_observations e JOIN evidence.observation_receipts r ON r.id=e.receipt_id WHERE r.collection_attempt_id=%s",
            (value.execution_id,),
        )
        assert cursor.fetchall() == [("0.123456789012345678901",)] * 1000
