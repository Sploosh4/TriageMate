"""Stop 3: additional actual-role boundaries on the retained synthetic database."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import json
import time
from unittest.mock import patch

import psycopg2
from psycopg2 import sql
import pytest

from test_import import RAW, direct, execution, importer, manage, query, verify
from backend.database.fixtures import FIXTURES


def snapshot(eid):
    return query(
        "SELECT to_jsonb(a) FROM evidence.collection_attempts a WHERE id=%s", (eid,)
    )


@pytest.mark.parametrize(
    "raw",
    [
        b"null",
        b"[]",
        b'{"origin":"synthetic","fixture_id":"x","data":null}',
        RAW.replace(b'"0.75"', b'"1e-2"'),
        RAW.replace(b'"0.75"', b'"-0.1"'),
        RAW.replace(b'"0.75"', b'"0.' + b"1" * 16384 + b'"'),
        RAW.replace(b'"origin":', b'"scope":"other","origin":'),
        RAW.replace(b'"origin":', b'"execution_id":"injected","origin":'),
        RAW.replace(b'"0.75"', b'"0.75","model_version":"\\u0000"'),
    ],
)
def test_more_direct_input_bypasses(raw):
    conn = importer.connect()
    try:
        result = direct(conn, raw)
        assert result["outcome"] == "failure"
        assert result["error_code"] == "invalid_input"
    finally:
        conn.rollback()
        conn.close()


@contextmanager
def deferred_fault(eid, failure_record=False):
    """Real deferred constraint trigger; synthetic fault, not a network interruption."""
    name = "epss_stop3_" + execution().replace("-", "")
    table = "collection_attempts" if failure_record else "epss_observations"
    predicate = (
        "NEW.id = '{}'::uuid AND NEW.outcome='failure'"
        if failure_record
        else "EXISTS(SELECT 1 FROM evidence.observation_receipts WHERE id=NEW.receipt_id AND collection_attempt_id='{}'::uuid)"
    ).format(eid)
    with manage.connect() as conn, conn.cursor() as cur:
        cur.execute(
            sql.SQL(
                "CREATE FUNCTION epss_import.{}() RETURNS trigger LANGUAGE plpgsql AS {}"
            ).format(
                sql.Identifier(name),
                sql.Literal(
                    "BEGIN IF "
                    + predicate
                    + " THEN RAISE EXCEPTION 'synthetic deferred fault' USING ERRCODE='23514'; END IF; RETURN NEW; END"
                ),
            )
        )
        cur.execute(
            sql.SQL(
                "CREATE CONSTRAINT TRIGGER {} AFTER INSERT ON evidence.{} DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION epss_import.{}()"
            ).format(sql.Identifier(name), sql.Identifier(table), sql.Identifier(name))
        )
    try:
        yield
    finally:
        with manage.connect() as conn, conn.cursor() as cur:
            cur.execute(
                sql.SQL("DROP TRIGGER {} ON evidence.{}").format(
                    sql.Identifier(name), sql.Identifier(table)
                )
            )
            cur.execute(
                sql.SQL("DROP FUNCTION epss_import.{}()").format(sql.Identifier(name))
            )


def test_deferred_evidence_failure_rolls_back_and_replays():
    eid = execution()
    before = query("SELECT count(*) FROM evidence.epss_observations")
    with deferred_fault(eid):
        result = importer.import_payload(eid, RAW)
        assert result["outcome"] == "failure"
        assert result["error_code"] == "persistence_failure"
    assert query("SELECT count(*) FROM evidence.epss_observations") == before
    assert query(
        "SELECT count(*) FROM evidence.observation_receipts WHERE collection_attempt_id=%s",
        (eid,),
    ) == [(0,)]
    recorded = snapshot(eid)
    assert importer.import_payload(eid, RAW) == result
    assert snapshot(eid) == recorded


def test_deferred_failure_recording_error_leaves_no_outcome():
    eid = execution()
    with deferred_fault(eid, failure_record=True):
        with pytest.raises(psycopg2.errors.CheckViolation):
            importer.import_payload(eid, b"invalid")
    assert snapshot(eid) == []
    assert importer._call("resolve", eid, b"invalid") is None
    assert query(
        "SELECT count(*) FROM evidence.observation_receipts WHERE collection_attempt_id=%s",
        (eid,),
    ) == [(0,)]


def test_evidence_failure_then_failure_recording_error_rolls_back_everything():
    eid = execution()
    before = query("SELECT count(*) FROM evidence.epss_observations")
    revisions = query("SELECT count(*) FROM evidence.source_revisions")
    with deferred_fault(eid), deferred_fault(eid, failure_record=True):
        with pytest.raises(psycopg2.errors.CheckViolation):
            importer.import_payload(eid, RAW)
    assert snapshot(eid) == []
    assert query("SELECT count(*) FROM evidence.epss_observations") == before
    assert query("SELECT count(*) FROM evidence.source_revisions") == revisions
    assert query(
        "SELECT count(*) FROM evidence.observation_receipts WHERE collection_attempt_id=%s",
        (eid,),
    ) == [(0,)]
    assert importer._call("resolve", eid, RAW) is None


@pytest.mark.parametrize("first_raw,second_raw", [(RAW, b"invalid"), (b"invalid", RAW)])
def test_conflict_waits_for_committed_success_or_failure(first_raw, second_raw):
    eid = execution()
    conn = importer.connect()
    try:
        first = direct(conn, first_raw, eid)
        with ThreadPoolExecutor(1) as pool:
            future = pool.submit(importer.import_payload, eid, second_raw)
            try:
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    waiting = query(
                        "SELECT count(*) FROM pg_stat_activity WHERE usename='tm_epss_importer' AND wait_event='advisory'"
                    )[0][0]
                    if waiting:
                        break
                    time.sleep(0.01)
                assert waiting == 1
                assert not future.done()
            finally:
                conn.commit()
            with pytest.raises(psycopg2.errors.InvalidParameterValue):
                future.result(timeout=3)
        assert importer._call("resolve", eid, first_raw) == first
        assert query(
            "SELECT count(*) FROM evidence.collection_attempts WHERE id=%s", (eid,)
        ) == [(1,)]
    finally:
        conn.close()


@pytest.mark.parametrize("raw", [RAW, b"invalid"])
def test_lost_ack_then_unavailable_resolver_preserves_commit(raw):
    eid = execution()
    original = importer._call
    calls = []
    recorded = []

    def fault(function, execution_id, data):
        calls.append(function)
        if function == "submit":
            original(function, execution_id, data)
            recorded.extend(snapshot(eid))
        raise psycopg2.OperationalError("simulated acknowledgement/resolver failure")

    with patch.object(importer, "_call", side_effect=fault):
        with pytest.raises(importer.OutcomeUnknown):
            importer.import_payload(eid, raw)
    assert calls == ["submit", "resolve"]  # no replacement write while uncertain
    assert snapshot(eid) == recorded
    result = importer.import_payload(eid, raw)
    assert result["outcome"] == ("success" if raw == RAW else "failure")
    assert snapshot(eid) == recorded


def test_actual_roles_all_product_table_writes_and_helpers_denied():
    tables = query(
        "SELECT table_schema,table_name FROM information_schema.tables WHERE table_schema IN ('evidence','mock_support') AND table_type='BASE TABLE'"
    )
    helpers = query(
        "SELECT p.proname, ARRAY(SELECT format_type(t,NULL) FROM unnest(p.proargtypes) t) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='epss_import' AND p.proname NOT IN ('submit','resolve')"
    )
    for reader in (False, True):
        conn = manage.connect(reader=True) if reader else importer.connect()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT current_user")
                assert cur.fetchone()[0] == (
                    "tm_mock_reader" if reader else "tm_epss_importer"
                )
            conn.rollback()
            for schema, table in tables:
                column = query(
                    "SELECT column_name FROM information_schema.columns WHERE table_schema=%s AND table_name=%s ORDER BY ordinal_position LIMIT 1",
                    (schema, table),
                )[0][0]
                with pytest.raises(psycopg2.errors.InsufficientPrivilege):
                    with conn.cursor() as cur:
                        if reader:
                            cur.execute("SET TRANSACTION READ WRITE")
                        cur.execute(
                            sql.SQL("UPDATE {} SET {}={} WHERE false").format(
                                sql.Identifier(schema, table),
                                sql.Identifier(column),
                                sql.Identifier(column),
                            )
                        )
                conn.rollback()
                for statement in (
                    "INSERT INTO {} DEFAULT VALUES",
                    "DELETE FROM {} WHERE false",
                    "TRUNCATE {}",
                ):
                    with pytest.raises(psycopg2.errors.InsufficientPrivilege):
                        with conn.cursor() as cur:
                            if reader:
                                cur.execute("SET TRANSACTION READ WRITE")
                            cur.execute(
                                sql.SQL(statement).format(sql.Identifier(schema, table))
                            )
                    conn.rollback()
            role = "tm_mock_reader" if reader else "tm_epss_importer"
            for helper, types in helpers:
                types = [
                    "evidence.collection_attempts" if t == "collection_attempts" else t
                    for t in types
                ]
                signature = "epss_import." + helper + "(" + ",".join(types) + ")"
                assert query(
                    "SELECT has_function_privilege(%s,%s,'EXECUTE')", (role, signature)
                ) == [(False,)]
                # Non-null arguments avoid PostgreSQL's STRICT null-folding shortcut.
                values = {
                    "text": "x",
                    "bytea": b"x",
                    "json": "{}",
                    "jsonb": "{}",
                    "numeric": "0",
                }
                values["evidence.collection_attempts"] = query(
                    "SELECT a::text FROM evidence.collection_attempts a LIMIT 1"
                )[0][0]
                with pytest.raises(psycopg2.errors.InsufficientPrivilege):
                    with conn.cursor() as cur:
                        cur.execute(
                            sql.SQL("SELECT epss_import.{}({})").format(
                                sql.Identifier(helper),
                                sql.SQL(",").join(sql.SQL("%s::" + t) for t in types),
                            ),
                            [values[t] for t in types],
                        )
                conn.rollback()
            for schema, table in tables:
                with conn.cursor() as cur:
                    statement = sql.SQL("SELECT * FROM {} LIMIT 0").format(
                        sql.Identifier(schema, table)
                    )
                    if reader:
                        cur.execute(statement)
                    else:
                        with pytest.raises(psycopg2.errors.InsufficientPrivilege):
                            cur.execute(statement)
                conn.rollback()
            if reader:
                for function in ("submit", "resolve"):
                    with pytest.raises(psycopg2.errors.InsufficientPrivilege):
                        with conn.cursor() as cur:
                            cur.execute(
                                sql.SQL(
                                    "SELECT epss_import.{}(%s::uuid,%s::bytea)"
                                ).format(sql.Identifier(function)),
                                (execution(), RAW),
                            )
                    conn.rollback()
        finally:
            conn.close()


def test_original_fixtures_and_non_epss_tables_unchanged():
    with manage.connect() as conn, conn.cursor() as cur:
        conn.set_session(isolation_level="REPEATABLE READ")
        fixtures = json.loads(FIXTURES.read_text())["tables"]
        originally_empty = [name for name, rows in fixtures.items() if not rows]
        assert len(originally_empty) == 6

        def retained_state():
            state = {}
            for name in originally_empty:
                cur.execute(
                    sql.SQL(
                        "SELECT encode(sha256(convert_to(to_jsonb(t)::text,'UTF8')),'hex') FROM evidence.{} t ORDER BY 1"
                    ).format(sql.Identifier(name))
                )
                state[name] = cur.fetchall()
            return state

        # Later authorized features can populate these tables. EPSS must leave
        # every retained row unchanged, not require deleting those features.
        before = retained_state()
        try:
            assert direct(conn)["outcome"] == "success"
            assert retained_state() == before
            verify(cur)
        finally:
            conn.rollback()
