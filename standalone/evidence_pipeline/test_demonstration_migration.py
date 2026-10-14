"""Supported OS distinctions and scoped evidence counts through the real reader."""

from backend.database import schema as database_schema

from uuid import uuid4

import pytest


from .test_store import db as database_fixture
from .test_devices import make
from .test_completeness import put

db = database_fixture


def test_predecessors_and_repeated_upgrade_preserve_authority(db):
    with db.cursor() as cur:
        database_schema.verify(cur)


@pytest.mark.parametrize(
    "value,expected",
    [
        ("Windows11", "Windows client"),
        ("WindowsServer2022", "Windows Server"),
        ("Windows", None),
        ("Linux", None),
        ("Ubuntu", None),
        ("WindowsServer2022 extra", None),
        (None, None),
    ],
)
def test_os_class_keeps_source_and_never_infers_purpose(db, value, expected):
    with db.cursor() as cur:
        database_schema.verify(cur)
    snapshot = make("Defender", [{"id": "synthetic-os-device", "osPlatform": value}])
    put(db, snapshot)
    with db.cursor() as cur:
        cur.execute("RESET ROLE")
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        cur.execute(
            "SELECT source_value,derived_os_class,device_purpose,manual_correction FROM evidence_pipeline.current_os_classes WHERE connection_id=%s",
            (snapshot.scope.connection_id,),
        )
        assert cur.fetchone() == (value, expected, None, None)


def test_empty_scope_and_false_values_have_inspectable_counts(db):
    with db.cursor() as cur:
        database_schema.verify(cur)
    a = make("Entra", [{"id": str(uuid4()), "isManaged": False}])
    b = make("Entra", [{"id": str(uuid4()), "displayName": "excluded synthetic scope"}])
    put(db, a)
    put(db, b)
    with db.cursor() as cur:
        cur.execute("RESET ROLE")
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        cur.execute(
            "SELECT * FROM evidence_pipeline.completeness_summary(ARRAY[]::uuid[])"
        )
        assert cur.fetchall() == [("whole-product", 0, 0, 0, None, "Not assessable")]
        cur.execute(
            "SELECT domain,populated,applicable,unknown_applicability FROM evidence_pipeline.completeness_summary(%s::uuid[])",
            ([a.scope.connection_id],),
        )
        assert cur.fetchall() == [("device", 2, 12, 22), ("whole-product", 2, 12, 22)]
        cur.execute(
            "SELECT value,populated FROM evidence_pipeline.current_product_completeness_cells WHERE scope_connections && %s::uuid[] AND field_name='entra.managed_flag'",
            ([a.scope.connection_id],),
        )
        assert cur.fetchone() == (False, True)


@pytest.mark.parametrize(
    "change",
    [
        "GRANT EXECUTE ON FUNCTION evidence_pipeline.completeness_summary(uuid[]) TO PUBLIC",
        "REVOKE EXECUTE ON FUNCTION pg_catalog.split_part(text,text,integer) FROM tm_mock_reader",
        "ALTER TABLE evidence.device_observations ALTER COLUMN os_architecture SET DEFAULT 'x64'",
        "REVOKE SELECT ON evidence_pipeline.current_os_classes FROM tm_mock_reader",
        "ALTER FUNCTION evidence_pipeline.check_cvrf_projection() SECURITY DEFINER",
        'REVOKE EXECUTE ON FUNCTION pg_catalog.jsonb_object_agg("any","any") FROM tm_pipeline_writer',
    ],
)
def test_authority_drift_rejected(db, change):
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute(change)
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cur)


def test_os_derivation_does_not_override_a_manual_correction(db):
    from .test_classification_store import call

    with db.cursor() as cur:
        database_schema.verify(cur)
    snapshot = make(
        "Defender", [{"id": "synthetic-corrected-device", "osPlatform": "Windows11"}]
    )
    put(db, snapshot)
    with db.cursor() as cur:
        cur.execute(
            "SELECT provider_device_id FROM evidence_pipeline.current_os_classes WHERE connection_id=%s",
            (snapshot.scope.connection_id,),
        )
        device = cur.fetchone()[0]
    call(
        db,
        str(uuid4()),
        device,
        chosen="Server",
        reason="Explicit synthetic manual correction",
    )
    with db.cursor() as cur:
        cur.execute(
            "SELECT derived_os_class,device_purpose,manual_correction,manual_reason FROM evidence_pipeline.current_os_classes WHERE connection_id=%s",
            (snapshot.scope.connection_id,),
        )
        assert cur.fetchone() == (
            "Windows client",
            None,
            "Server",
            "Explicit synthetic manual correction",
        )


@pytest.mark.parametrize(
    "source",
    ["Debian", "Apache HTTP Server", "Apache Tomcat", "Samba", "Palo Alto Networks"],
)
def test_enabled_vendor_synthetic_contract_persists_with_public_authority(db, source):
    from datetime import datetime, timezone
    from .test_advisory_feeds import fixture
    from standalone.evidence_pipeline.parsing.public_snapshot import PublicSnapshot
    from standalone.evidence_pipeline.persistence.authority import authorize_connection
    from standalone.evidence_pipeline.persistence.public_store import persist_public

    scope, payload = fixture(source)
    now = datetime.now(timezone.utc)
    snapshot = PublicSnapshot(scope, str(uuid4()), now, now, "success", True, payload)
    with db.cursor() as cur:
        database_schema.verify(cur)
        authorize_connection(cur, snapshot)
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
    persist_public(db, snapshot)
    with db.cursor() as cur:
        cur.execute("SET CONSTRAINTS ALL IMMEDIATE")
        cur.execute("RESET ROLE")
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        cur.execute(
            "SELECT count(*) FROM evidence_pipeline.current_public_references WHERE connection_id=%s",
            (scope.connection_id,),
        )
        assert cur.fetchone()[0] > 0


def test_large_osv_page_persists_and_replays_after_upgrade(db, tmp_path):
    from .test_osv_query_store import collection, setup, flush
    from standalone.evidence_pipeline.persistence.public_store import persist_public

    with db.cursor() as cur:
        database_schema.verify(cur)
    # Exact wire bytes, including insignificant whitespace, remain evidence.
    value = collection(tmp_path, pages=[b" " * 45_000_001 + b'{"vulns":[]}'])
    setup(db, value)
    assert not persist_public(db, value)["replayed"]
    flush(db)
    assert persist_public(db, value)["replayed"]
    with db.cursor() as cur:
        cur.execute("RESET SESSION AUTHORIZATION")
        cur.execute(
            "SELECT octet_length(wire) FROM evidence_pipeline.osv_query_pages WHERE attempt_id=%s",
            (value.execution_id,),
        )
        assert cur.fetchone()[0] > 45_000_000


def test_reader_supports_long_source_and_uuid_lists(db):
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        identifiers = [str(uuid4()) for _ in range(12)]
        cur.execute(
            "SELECT connection_id FROM evidence_pipeline.product_collection_coverage WHERE connection_id=ANY(%s::uuid[])",
            (identifiers,),
        )
        assert cur.fetchall() == []
        cur.execute(
            "SELECT count(*) FROM evidence_pipeline.product_collection_coverage WHERE completeness_domain IS NOT NULL"
        )
        assert cur.fetchone()[0] >= 0


def test_overlapping_scopes_count_inspectable_cells_not_unique_devices(db):
    tenant, native, registration = (str(uuid4()) for _ in range(3))
    with db.cursor() as cur:
        database_schema.verify(cur)
    scopes = []
    for managed in (False, True):
        snapshot = make(
            "Entra",
            [{"id": native, "deviceId": registration, "isManaged": managed}],
            tenant=tenant,
        )
        put(db, snapshot)
        scopes.append(snapshot.scope.connection_id)
    with db.cursor() as cur:
        cur.execute("RESET ROLE")
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        for selected in ([scopes[0]], scopes, scopes + scopes):
            cur.execute(
                "SELECT populated,applicable,unknown_applicability FROM evidence_pipeline.completeness_summary(%s::uuid[]) WHERE domain='whole-product'",
                (selected,),
            )
            summary = cur.fetchone()
            cur.execute(
                "SELECT count(*) FILTER(WHERE populated AND applicability='applicable'),count(*) FILTER(WHERE applicability='applicable'),count(*) FILTER(WHERE applicability='unknown') FROM evidence_pipeline.current_product_completeness_cells WHERE scope_connections && %s::uuid[]",
                (selected,),
            )
            assert summary == cur.fetchone()
            cur.execute(
                "SELECT value FROM evidence_pipeline.current_product_completeness_cells WHERE scope_connections && %s::uuid[] AND field_name='entra.managed_flag' ORDER BY value::text",
                (selected,),
            )
            assert cur.fetchall() == (
                [(False,)] if len(selected) == 1 else [(False,), (True,)]
            )
