"""Actual-role tests against the one retained database; no service, database or restore creation."""

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sys
import uuid
from unittest.mock import patch

import psycopg2
import pytest

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE.parent), str(HERE.parents[2])]
import manage  # noqa: E402 — standalone script path bootstrap
from baseline import verify  # noqa: E402 — standalone script path bootstrap
from backend.database.schema import verify_supported as verify_installed  # noqa: E402
from standalone import synthetic_epss_import as importer  # noqa: E402 — standalone script path bootstrap
from standalone.synthetic_epss import parse_payload  # noqa: E402 — standalone script path bootstrap

RAW = manage.ROOT / "standalone/fixtures/synthetic_epss_v1.json"
RAW = RAW.read_bytes()


def execution():
    return str(uuid.uuid4())


def direct(conn, raw=RAW, eid=None):
    with conn.cursor() as cur:
        cur.execute(
            "SELECT epss_import.submit(%s::uuid,%s::bytea)", (eid or execution(), raw)
        )
        return cur.fetchone()[0]


def query(q, args=()):
    with manage.connect() as conn, conn.cursor() as cur:
        cur.execute(q, args)
        return cur.fetchall()


def test_exact_storage_replay_and_changed_input():
    eid = execution()
    result = importer.import_payload(eid, RAW)
    assert result["outcome"] == "success"
    assert importer.import_payload(eid, RAW) == result
    with pytest.raises(psycopg2.errors.InvalidParameterValue):
        importer.import_payload(eid, RAW + b" ")
    rows = query(
        """SELECT e.cve_id,e.probability,e.percentile,e.model_version,v.content_hash
      FROM evidence.epss_observations e JOIN evidence.observation_receipts r ON r.id=e.receipt_id
      JOIN evidence.source_revisions v ON v.id=r.source_revision_id WHERE r.collection_attempt_id=%s ORDER BY e.cve_id""",
        (eid,),
    )
    for actual, expected in zip(rows, parse_payload(RAW).observations, strict=True):
        assert actual == (
            expected.cve_id,
            expected.probability,
            expected.percentile,
            expected.model_version,
            expected.content_hash,
        )
    assert query(
        "SELECT count(*) FROM evidence.collection_attempts WHERE id=%s", (eid,)
    ) == [(1,)]


def test_new_execution_reuses_revision_and_retains_receipts():
    a, b = execution(), execution()
    importer.import_payload(a, RAW)
    importer.import_payload(b, RAW)
    assert query(
        "SELECT count(*),count(DISTINCT source_revision_id),count(DISTINCT collection_attempt_id) FROM evidence.observation_receipts WHERE collection_attempt_id IN (%s,%s)",
        (a, b),
    ) == [(4, 2, 2)]
    changed = RAW.replace(b'"0.75"', b'"0.76"')
    c = execution()
    importer.import_payload(c, changed)
    assert query(
        "SELECT count(*),count(DISTINCT source_revision_id) FROM evidence.observation_receipts WHERE collection_attempt_id IN (%s,%s,%s)",
        (a, b, c),
    ) == [(6, 3)]


def test_empty_and_failure_replay_preserve_evidence():
    before = query("SELECT count(*) FROM evidence.epss_observations")
    empty = json.dumps(
        {"origin": "synthetic", "fixture_id": "empty-test", "data": []}
    ).encode()
    empty_id = execution()
    assert importer.import_payload(empty_id, empty)["outcome"] == "success"
    invalid_id = execution()
    invalid = RAW.replace(b'"0.75"', b'"1.75"')
    failed = importer.import_payload(invalid_id, invalid)
    assert failed["outcome"] == "failure" and failed["error_code"] == "invalid_input"
    assert importer.import_payload(invalid_id, invalid) == failed
    with pytest.raises(psycopg2.errors.InvalidParameterValue):
        importer.import_payload(invalid_id, RAW)
    assert query("SELECT count(*) FROM evidence.epss_observations") == before
    assert query(
        "SELECT count(*) FROM evidence.observation_receipts WHERE collection_attempt_id IN (%s,%s)",
        (empty_id, invalid_id),
    ) == [(0,)]


@pytest.mark.parametrize(
    "raw",
    [
        b"bad",
        b"\xff",
        b'{"origin":"synthetic","origin":"synthetic"}',
        RAW.replace(b'"synthetic"', b"null"),
        RAW.replace(b'"synthetic"', b'"public"'),
        RAW.replace(b'"0.75"', b"0.75"),
        RAW.replace(b'"0.75"', b"true"),
        RAW.replace(b'"0.75"', b'"NaN"'),
        RAW.replace(b"2026-09-11", b"2026-02-30"),
        RAW.replace(b"CVE-2099-900001", b"CVE-2099-10001"),
        RAW.replace(b'"0.75"', b'"0.75", "percentile":"0.2"'),
        RAW.replace(b'"date":', b'"unexpected":1,"date":'),
    ],
)
def test_database_rejects_invalid_input_without_python_parser(raw):
    conn = importer.connect()
    try:
        eid = execution()
        result = direct(conn, raw, eid)
        assert result["outcome"] == "failure"
        # Stored in this transaction; rollback below leaves the accepted fixtures intact.
        with conn.cursor() as cur:
            cur.execute("SELECT epss_import.resolve(%s::uuid,%s::bytea)", (eid, raw))
            assert cur.fetchone()[0] == result
    finally:
        conn.rollback()
        conn.close()


def test_partial_persistence_rollback_via_actual_role():
    # Temporary fault constraint targets only this execution's second receipt.
    # The importer uses its actual login, and the constraint is removed in finally.
    from psycopg2 import sql

    eid = execution()
    payload = json.loads(RAW)
    payload["fixture_id"] = "rollback-test"
    new_cve = "CVE-2099-8" + str(uuid.uuid4().int)
    payload["data"][0]["cve"] = new_cve
    fault_raw = json.dumps(payload).encode()
    name = "epss_fault_" + uuid.uuid4().hex
    with manage.connect() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT epss_import.identity('receipt',%s||'/'||epss_import.identity('revision',%s)::text)",
            (
                eid,
                "CVE-2099-900002/2026-09-11/"
                + next(
                    o.content_hash
                    for o in parse_payload(fault_raw).observations
                    if o.cve_id == "CVE-2099-900002"
                ),
            ),
        )
        receipt = cur.fetchone()[0]
        cur.execute(
            sql.SQL(
                "ALTER TABLE evidence.epss_observations ADD CONSTRAINT {} CHECK(receipt_id<>%s::uuid) NOT VALID"
            ).format(sql.Identifier(name)),
            (receipt,),
        )
    before = query("SELECT count(*) FROM evidence.epss_observations")
    before_revisions = query("SELECT count(*) FROM evidence.source_revisions")
    try:
        result = importer.import_payload(eid, fault_raw)
        assert (
            result["outcome"] == "failure"
            and result["error_code"] == "persistence_failure"
        )
        assert query(
            "SELECT count(*) FROM evidence.observation_receipts WHERE collection_attempt_id=%s",
            (eid,),
        ) == [(0,)]
        assert query("SELECT count(*) FROM evidence.epss_observations") == before
        assert importer.import_payload(eid, fault_raw) == result
        assert (
            query("SELECT count(*) FROM evidence.source_revisions") == before_revisions
        )
        assert query(
            "SELECT count(*) FROM evidence.vulnerabilities WHERE cve_id=%s", (new_cve,)
        ) == [(0,)]
    finally:
        with manage.connect() as conn, conn.cursor() as cur:
            cur.execute(
                sql.SQL(
                    "ALTER TABLE evidence.epss_observations DROP CONSTRAINT {}"
                ).format(sql.Identifier(name))
            )


def test_actual_login_cannot_write_or_escalate():
    forbidden = [
        "INSERT INTO evidence.vulnerabilities VALUES('CVE-2099-9999999')",
        "UPDATE evidence.collection_attempts SET outcome='success'",
        "DELETE FROM evidence.epss_observations",
        "CREATE TABLE public.import_escape(id int)",
        "CREATE TEMP TABLE import_escape(id int)",
        "SET ROLE tm_epss_function",
        "SET ROLE tm_mock_owner",
        "SELECT epss_import.identity('a','b')",
        "SELECT pg_read_file('/etc/passwd')",
        "UPDATE mock_support.mock_snapshot_selections SET connection_id=connection_id",
        "INSERT INTO evidence.notifications DEFAULT VALUES",
    ]
    conn = importer.connect()
    try:
        for statement in forbidden:
            with pytest.raises(psycopg2.errors.InsufficientPrivilege):
                with conn.cursor() as cur:
                    cur.execute(statement)
            conn.rollback()
    finally:
        conn.close()
    conn = manage.connect(reader=True)
    try:
        with pytest.raises(psycopg2.errors.InsufficientPrivilege):
            direct(conn)
    finally:
        conn.rollback()
        conn.close()


def test_concurrent_replay_and_competing_input():
    eid = execution()
    with ThreadPoolExecutor(2) as pool:
        results = list(pool.map(lambda _: importer.import_payload(eid, RAW), range(2)))
    assert results[0] == results[1]
    assert query(
        "SELECT count(*) FROM evidence.observation_receipts WHERE collection_attempt_id=%s",
        (eid,),
    ) == [(2,)]
    another = execution()

    def competing(raw):
        try:
            return importer.import_payload(another, raw)["outcome"]
        except psycopg2.errors.InvalidParameterValue:
            return "conflict"

    with ThreadPoolExecutor(2) as pool:
        results = list(pool.map(competing, [RAW, RAW + b" "]))
    assert sorted(results) == ["conflict", "success"]


def test_uncertain_commit_resolves_recorded_outcome():
    original = importer._call
    eid = execution()
    calls = []

    def lost_ack(function, execution, raw):
        calls.append(function)
        result = original(function, execution, raw)
        if function == "submit" and len(calls) == 1:
            raise psycopg2.OperationalError("Simulated lost commit acknowledgement")
        return result

    with patch.object(importer, "_call", side_effect=lost_ack):
        assert importer.import_payload(eid, RAW)["outcome"] == "success"
    assert calls == ["submit", "resolve"]
    assert query(
        "SELECT count(*) FROM evidence.observation_receipts WHERE collection_attempt_id=%s",
        (eid,),
    ) == [(2,)]
    with patch.object(
        importer, "_call", side_effect=psycopg2.OperationalError("offline")
    ):
        with pytest.raises(importer.OutcomeUnknown):
            importer.import_payload(execution(), RAW)


def test_baseline_exact_and_unexplained_extras_rejected():
    with manage.connect() as conn, conn.cursor() as cur:
        verify(cur)
        cur.execute("SAVEPOINT unexplained")
        cur.execute("INSERT INTO evidence.vulnerabilities VALUES('CVE-2099-8888888')")
        with pytest.raises(AssertionError):
            verify(cur)
        cur.execute("ROLLBACK TO SAVEPOINT unexplained")
        cur.execute("SAVEPOINT altered")
        cur.execute(
            "UPDATE evidence.epss_observations SET probability=0.99 WHERE id=(SELECT id FROM evidence.epss_observations WHERE cve_id='CVE-2099-10001' LIMIT 1)"
        )
        with pytest.raises(AssertionError):
            verify(cur)
        cur.execute("ROLLBACK TO SAVEPOINT altered")
        # Validate the original schema plus every explicitly recorded additive
        # migration. This rejects unexplained drift without treating later
        # accepted evidence migrations as corruption.
        verify_installed(cur)


def test_failure_recording_failure_is_not_reported_as_persisted():
    from psycopg2 import sql

    eid = execution()
    name = "epss_failure_fault_" + uuid.uuid4().hex
    with manage.connect() as conn, conn.cursor() as cur:
        cur.execute(
            sql.SQL(
                "ALTER TABLE evidence.collection_attempts ADD CONSTRAINT {} CHECK(id<>%s::uuid) NOT VALID"
            ).format(sql.Identifier(name)),
            (eid,),
        )
    try:
        with pytest.raises(psycopg2.errors.CheckViolation):
            importer.import_payload(eid, b"invalid")
        assert query(
            "SELECT count(*) FROM evidence.collection_attempts WHERE id=%s", (eid,)
        ) == [(0,)]
    finally:
        with manage.connect() as conn, conn.cursor() as cur:
            cur.execute(
                sql.SQL(
                    "ALTER TABLE evidence.collection_attempts DROP CONSTRAINT {}"
                ).format(sql.Identifier(name))
            )


def test_uncertain_failed_commit_and_aborted_commit():
    original = importer._call
    for raw in (RAW, b"invalid"):
        eid = execution()
        calls = []

        def lost(function, execution, raw):
            calls.append(function)
            result = original(function, execution, raw)
            if len(calls) == 1:
                raise psycopg2.OperationalError("Lost acknowledgement")
            return result

        with patch.object(importer, "_call", side_effect=lost):
            result = importer.import_payload(eid, raw)
        assert calls == ["submit", "resolve"]
        assert original("resolve", eid, raw) == result
    eid = execution()
    calls = []

    def aborted(function, execution, raw):
        calls.append(function)
        if len(calls) == 1:
            raise psycopg2.OperationalError("Failed before commit")
        return original(function, execution, raw)

    with patch.object(importer, "_call", side_effect=aborted):
        assert importer.import_payload(eid, RAW)["outcome"] == "success"
    assert calls == ["submit", "resolve", "submit"]


def test_foreign_execution_id_cannot_be_reused():
    eid = query(
        "SELECT id FROM evidence.collection_attempts WHERE input_fingerprint IS NULL ORDER BY id LIMIT 1"
    )[0][0]
    before = query(
        "SELECT row_to_json(t) FROM evidence.collection_attempts t WHERE id=%s", (eid,)
    )
    with pytest.raises(psycopg2.errors.InvalidParameterValue):
        importer.import_payload(eid, RAW)
    assert (
        query(
            "SELECT row_to_json(t) FROM evidence.collection_attempts t WHERE id=%s",
            (eid,),
        )
        == before
    )


def test_installed_schema_drift_is_rejected():
    conn = manage.connect()
    try:
        with conn.cursor() as cur:
            verify_installed(cur)
            cur.execute(
                "ALTER TABLE evidence.epss_observations ADD COLUMN unexpected text"
            )
            with pytest.raises(
                (AssertionError, ValueError), match="schema/authority differs"
            ):
                verify_installed(cur)
    finally:
        conn.rollback()
        conn.close()


@pytest.mark.parametrize(
    "changes",
    [
        {"model_version": "\u00a0"},
        {"model_version": False},
        {"model_version": " "},
        {"epss": None},
        {"date": None},
        {"cve": None},
        {"percentile": "Infinity"},
    ],
)
def test_direct_record_validation_matches_parser(changes):
    data = json.loads(RAW)
    data["data"][0].update(changes)
    conn = importer.connect()
    try:
        assert direct(conn, json.dumps(data).encode())["outcome"] == "failure"
    finally:
        conn.rollback()
        conn.close()
