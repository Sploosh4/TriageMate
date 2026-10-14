"""Synthetic current device identity groups, isolated by generated tenant IDs."""

from backend.database import schema as database_schema

from dataclasses import replace
from datetime import timedelta
import json
from uuid import uuid4

import pytest

from standalone.evidence_pipeline.persistence.authority import authorize_connection
from standalone.evidence_pipeline.persistence.store import persist_devices
from .test_store import db as db_fixture, snapshot as snapshot_fixture

db = db_fixture
snapshot = snapshot_fixture


def stage(db, value):
    with db.cursor() as cur:
        authorize_connection(cur, value)
    persist_devices(db, value)


def links(db, tenant):
    with db.cursor() as cur:
        cur.execute(
            "SELECT computer_key,match_basis,source_name FROM evidence_pipeline.current_computer_links l JOIN evidence.microsoft_tenants t ON t.id=l.tenant_id WHERE t.external_tenant_id=%s ORDER BY source_name,provider_device_id",
            (tenant,),
        )
        return cur.fetchall()


@pytest.fixture
def identities(db, snapshot):
    with db.cursor() as cur:
        database_schema.verify(cur)
    stage(db, snapshot)
    registration = json.loads(snapshot.payload)[0]["deviceId"]
    intune = replace(
        snapshot,
        scope=replace(snapshot.scope, connection_id=str(uuid4()), source="Intune"),
        execution_id=str(uuid4()),
        payload=json.dumps(
            [
                {
                    "id": str(uuid4()),
                    "azureADDeviceId": registration,
                    "deviceName": "Different synthetic name",
                }
            ]
        ).encode(),
    )
    stage(db, intune)
    return db, snapshot, intune


def test_shared_guid_matches_without_equal_names(identities):
    db, first, _ = identities
    values = links(db, first.scope.tenant_id)
    assert len(values) == 2 and values[0][0] == values[1][0]
    assert {row[1] for row in values} == {"microsoft_registration_id"}


def test_same_native_device_in_overlapping_scopes_is_not_a_duplicate(identities):
    db, first, second = identities
    overlapping = replace(
        second,
        scope=replace(second.scope, connection_id=str(uuid4())),
        execution_id=str(uuid4()),
    )
    stage(db, overlapping)
    values = links(db, first.scope.tenant_id)
    assert len(values) == 3  # Preserve all source observations and their receipts.
    assert len({row[0] for row in values}) == 1
    assert {row[1] for row in values} == {"microsoft_registration_id"}
    with db.cursor() as cur:
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        cur.execute(
            "SELECT count(DISTINCT computer_key),count(*) FILTER(WHERE field_key='intune.native_device_id'),count(DISTINCT connection_id) FILTER(WHERE field_key='intune.native_device_id'),count(*) FILTER(WHERE field_key='microsoft.registration_id') FROM evidence_pipeline.current_completeness_cells c JOIN evidence.microsoft_tenants t ON t.id=c.tenant_id WHERE t.external_tenant_id=%s",
            (first.scope.tenant_id,),
        )
        # Scope observations stay inspectable; only shared identity is counted once.
        assert cur.fetchone() == (1, 2, 2, 1)


def test_duplicate_guid_within_source_keeps_every_record_separate(identities):
    db, first, second = identities
    raw = json.loads(second.payload)
    raw.append({**raw[0], "id": str(uuid4())})
    persist_devices(
        db,
        replace(
            second,
            execution_id=str(uuid4()),
            finished_at=second.finished_at + timedelta(seconds=1),
            payload=json.dumps(raw).encode(),
        ),
    )
    values = links(db, first.scope.tenant_id)
    assert len(values) == len({row[0] for row in values}) == 3
    assert {row[1] for row in values} == {"ambiguous_registration_id"}


def test_overlapping_native_device_with_conflicting_registration_stays_unknown(
    identities,
):
    db, first, second = identities
    raw = json.loads(second.payload)
    raw[0]["azureADDeviceId"] = str(uuid4())
    stage(
        db,
        replace(
            second,
            scope=replace(second.scope, connection_id=str(uuid4())),
            execution_id=str(uuid4()),
            payload=json.dumps(raw).encode(),
        ),
    )
    values = links(db, first.scope.tenant_id)
    assert len(values) == len({row[0] for row in values}) == 3
    assert {row[1] for row in values} == {"ambiguous_registration_id"}


def test_failure_keeps_links_and_complete_empty_removes_source(identities):
    db, first, second = identities
    persist_devices(
        db,
        replace(
            second,
            execution_id=str(uuid4()),
            finished_at=second.finished_at + timedelta(seconds=1),
            outcome="failure",
            complete=False,
            payload=b"",
            error_code="unavailable",
        ),
    )
    assert len(links(db, first.scope.tenant_id)) == 2
    persist_devices(
        db,
        replace(
            second,
            execution_id=str(uuid4()),
            finished_at=second.finished_at + timedelta(seconds=2),
            payload=b"[]",
        ),
    )
    assert len(links(db, first.scope.tenant_id)) == 1


def test_missing_ids_do_not_match_on_name(db, snapshot):
    with db.cursor() as cur:
        database_schema.verify(cur)
    raw = json.loads(snapshot.payload)[0]
    raw.pop("deviceId")
    value = replace(
        snapshot, payload=json.dumps([raw, {**raw, "id": str(uuid4())}]).encode()
    )
    stage(db, value)
    values = links(db, value.scope.tenant_id)
    assert len({row[0] for row in values}) == 2
    assert {row[1] for row in values} == {"missing_or_invalid_registration_id"}


def test_same_registration_in_another_tenant_stays_separate(identities):
    db, first, _ = identities
    other = replace(
        first,
        scope=replace(first.scope, connection_id=str(uuid4()), tenant_id=str(uuid4())),
        execution_id=str(uuid4()),
    )
    stage(db, other)
    assert (
        links(db, first.scope.tenant_id)[0][0] != links(db, other.scope.tenant_id)[0][0]
    )


def test_actual_reader_can_query_computer_counts(identities):
    db, first, _ = identities
    with db.cursor() as cur:
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_mock_reader")
        cur.execute(
            "SELECT provider_record_count FROM evidence_pipeline.current_computers c JOIN evidence.microsoft_tenants t ON t.id=c.tenant_id WHERE t.external_tenant_id=%s",
            (first.scope.tenant_id,),
        )
        assert cur.fetchall() == [(2,)]


@pytest.mark.full_baseline
def test_identity_upgrade_repeats_and_rejects_view_drift(db):

    from .test_attribution import verify as verify_data

    with db.cursor() as cur:
        database_schema.verify(cur)
        verify_data(cur)
        cur.execute(
            "CREATE OR REPLACE VIEW evidence_pipeline.current_computers AS SELECT computer_key,match_basis,tenant_id,origin,count(*) AS provider_record_count FROM evidence_pipeline.current_computer_links WHERE false GROUP BY computer_key,match_basis,tenant_id,origin"
        )
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cur)


def test_repeated_native_device_without_registration_keeps_one_identity(db, snapshot):
    """Missing cross-provider GUID must not split an exact source-native identity."""

    with db.cursor() as cur:
        database_schema.verify(cur)
    raw = json.loads(snapshot.payload)
    raw[0].pop("deviceId")
    first = replace(snapshot, payload=json.dumps(raw).encode())
    second = replace(
        first,
        scope=replace(first.scope, connection_id=str(uuid4())),
        execution_id=str(uuid4()),
    )
    stage(db, first)
    stage(db, second)
    values = links(db, first.scope.tenant_id)
    assert len(values) == 2
    assert len({row[0] for row in values}) == 1
    assert {row[1] for row in values} == {"missing_or_invalid_registration_id"}


@pytest.mark.parametrize("boundary", ["tenant", "source", "registration"])
def test_native_scope_identity_does_not_cross_evidence_boundaries(
    db, snapshot, boundary
):

    with db.cursor() as cur:
        database_schema.verify(cur)
    raw = json.loads(snapshot.payload)
    raw[0].pop("deviceId")
    first = replace(snapshot, payload=json.dumps(raw).encode())
    other_scope = replace(first.scope, connection_id=str(uuid4()))
    if boundary == "tenant":
        other_scope = replace(other_scope, tenant_id=str(uuid4()))
    elif boundary == "source":
        other_scope = replace(other_scope, source="Intune")
    else:
        raw[0]["deviceId"] = str(uuid4())
    second = replace(
        first,
        scope=other_scope,
        execution_id=str(uuid4()),
        payload=json.dumps(raw).encode(),
    )
    stage(db, first)
    stage(db, second)
    with db.cursor() as cur:
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        cur.execute(
            "SELECT count(*), count(DISTINCT computer_key) FROM "
            "evidence_pipeline.current_computer_links WHERE connection_id=ANY(%s::uuid[])",
            ([first.scope.connection_id, second.scope.connection_id],),
        )
        assert cur.fetchone() == (2, 2)


@pytest.mark.parametrize("missing_registration", [False, True])
def test_other_native_id_conflict_does_not_split_repeated_native_observations(
    identities,
    missing_registration,
):

    db, first, second = identities
    with db.cursor() as cur:
        database_schema.verify(cur)
    overlapping = replace(
        second,
        scope=replace(second.scope, connection_id=str(uuid4())),
        execution_id=str(uuid4()),
    )
    if missing_registration:
        raw_overlap = json.loads(overlapping.payload)
        raw_overlap[0].pop("azureADDeviceId")
        overlapping = replace(overlapping, payload=json.dumps(raw_overlap).encode())
    stage(db, overlapping)
    raw = json.loads(second.payload)
    raw[0]["id"] = str(uuid4())
    other = replace(
        second,
        scope=replace(second.scope, connection_id=str(uuid4())),
        execution_id=str(uuid4()),
        payload=json.dumps(raw).encode(),
    )
    stage(db, other)
    with db.cursor() as cur:
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        cur.execute(
            "SELECT source_name,native_device_id,count(*),count(DISTINCT computer_key),min(match_basis) FROM evidence_pipeline.current_computer_links l JOIN evidence.microsoft_tenants t ON t.id=l.tenant_id WHERE t.external_tenant_id=%s GROUP BY source_name,native_device_id",
            (first.scope.tenant_id,),
        )
        rows = cur.fetchall()
        assert len(rows) == 3
        assert sorted(row[2] for row in rows) == [1, 1, 2]
        assert all(
            row[3] == 1 and row[4] == "ambiguous_registration_id" for row in rows
        )
        cur.execute(
            "SELECT count(DISTINCT computer_key) FROM evidence_pipeline.current_completeness_cells c JOIN evidence.microsoft_tenants t ON t.id=c.tenant_id WHERE t.external_tenant_id=%s",
            (first.scope.tenant_id,),
        )
        assert cur.fetchone() == (3,)
        cur.execute(
            "SELECT count(*),sum(provider_record_count) FROM evidence_pipeline.current_computers c JOIN evidence.microsoft_tenants t ON t.id=c.tenant_id WHERE t.external_tenant_id=%s",
            (first.scope.tenant_id,),
        )
        assert cur.fetchone() == (3, 4)


def test_conflicting_scope_identity_upgrade_rejects_view_drift(db):

    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute(
            "CREATE OR REPLACE VIEW evidence_pipeline.current_computers AS "
            "SELECT computer_key,match_basis,tenant_id,origin,count(*) AS provider_record_count "
            "FROM evidence_pipeline.current_computer_links WHERE false "
            "GROUP BY computer_key,match_basis,tenant_id,origin"
        )
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cur)
