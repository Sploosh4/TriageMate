"""Synthetic legacy-public preservation; never connects to the actual runner."""

from contextlib import closing, contextmanager
import gzip
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess

import psycopg2
import pytest
from psycopg2.extras import Json

from backend.database import retained_runner, schema
from backend.database.adoption import adopt
from backend.database.backup import capture, restore_isolated, _environment
from backend.database.baseline.catalogue import fingerprint
from backend.database.baseline.profiles import identify_layout
from backend.database.credentials import read_credentials
from standalone.evidence_pipeline.test_bootstrap import (
    isolated_database,
    postgres_runtime,
)

FIXTURES = Path(__file__).with_name("fixtures") / "retained_runner"


def passwords():
    return schema.InstallPasswords(*(secrets.token_urlsafe(32) for _ in range(3)))


@contextmanager
def runner_database(monkeypatch):
    with isolated_database(monkeypatch, owner="triagemate", name="triagemate") as db:
        password = read_credentials(
            db.WORK / "credentials.json", frozenset({"owner", "reader"})
        )["owner"]
        with (
            closing(
                psycopg2.connect(
                    host=db.TARGET.host,
                    port=db.PORT,
                    dbname=db.DB,
                    user="triagemate",
                    password=password,
                )
            ) as conn,
            conn,
            conn.cursor() as cur,
        ):
            cur.execute(
                "CREATE ROLE tm_mock_owner LOGIN SUPERUSER PASSWORD %s", (password,)
            )
        yield db


def restore_fixture(db, tmp_path):
    manifest = json.loads((FIXTURES / "manifest.json").read_text())
    assert manifest["origin"] == "synthetic"
    raw = (FIXTURES / manifest["archive"]).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == manifest["sha256"]
    expanded = gzip.decompress(raw)
    assert hashlib.sha256(expanded).hexdigest() == manifest["uncompressed_sha256"]
    archive = tmp_path / "retained-runner.dump"
    with archive.open("xb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(expanded)
    binary = postgres_runtime()[1] / "pg_restore"
    with closing(db.connect()) as conn:
        with conn, conn.cursor() as cur:
            schema.provision_empty(
                cur, database=db.DB, passwords=passwords(), profile="runner"
            )
            retained_runner.prepare_isolated_restore(cur)
        result = subprocess.run(
            [
                str(binary),
                "--single-transaction",
                "--exit-on-error",
                "--no-password",
                "--dbname",
                db.DB,
                str(archive),
            ],
            env=_environment(conn),
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, result.stderr
        with conn, conn.cursor() as cur:
            cur.execute(
                "COMMENT ON DATABASE triagemate IS %s",
                (json.dumps(manifest["annotation"]),),
            )
            assert schema.verify_predecessor(cur) == "runner"


def test_companion_is_exact_and_does_not_change_default_ledger():
    ordinary = schema.artifacts()
    assert all(not name.startswith(retained_runner.PREFIX) for name in ordinary)
    extended = schema.artifacts(retained=True)
    assert extended == {**ordinary, **retained_runner.artifacts()}
    for old in (False, True):
        expected = retained_runner.contract(predecessor=old)
        assert identify_layout(expected) == ("runner", old)
        for category in expected:
            with pytest.raises(ValueError, match="exactly one"):
                identify_layout({**expected, category: "0" * 64})


def test_retained_runner_backup_adoption_and_drift(monkeypatch, tmp_path):
    from standalone.evidence_pipeline.test_attribution import verify as attribution

    binary = postgres_runtime()[1]
    with runner_database(monkeypatch) as source, runner_database(monkeypatch) as target:
        restore_fixture(source, tmp_path)
        with closing(source.connect()) as conn, conn, conn.cursor() as cur:
            assert fingerprint(cur) == retained_runner.contract()
            cur.execute("SAVEPOINT intact")
            changes = [
                ("ALTER ROLE triagemate_test_application LOGIN", "role authority"),
                (
                    "ALTER ROLE triagemate_retention_executor SUPERUSER",
                    "role authority",
                ),
                ("GRANT triagemate_test_application TO triagemate", "role authority"),
                (
                    "ALTER ROLE triagemate_retention_approver SET search_path='public'",
                    "role authority",
                ),
                (
                    "UPDATE public.alembic_version SET version_num='057'",
                    "public revision",
                ),
                ("CREATE TABLE public.unexpected(id integer)", "exactly one"),
                (
                    "REVOKE EXECUTE ON FUNCTION pg_catalog.count() FROM triagemate_retention_executor",
                    "exactly one",
                ),
                (
                    "UPDATE evidence_pipeline.installation SET signature='{}'::jsonb",
                    "signature differs",
                ),
            ]
            for statement, message in changes:
                cur.execute(statement)
                with pytest.raises(ValueError, match=message):
                    schema.verify_predecessor(cur)
                cur.execute("ROLLBACK TO SAVEPOINT intact")
            # Preserved legacy data is not a requirement to restore its product feature.
            cur.execute(
                "INSERT INTO public.vulnerabilities(vulnerability_id,hostname,priority_score,risk_band,case_key) "
                "VALUES ('synthetic-retention-probe','synthetic.invalid',0,'synthetic','synthetic-preservation')"
            )
            cur.execute("SELECT nextval('evidence_pipeline.operation_events_id_seq')")
        parent = tmp_path / "backup"
        parent.mkdir(mode=0o700)
        directory = parent / "source"
        capture(source, directory, binary=binary / "pg_dump")
        with pytest.raises(ValueError, match="different isolated"):
            restore_isolated(
                source, directory, binary=binary / "pg_restore", passwords=passwords()
            )
        restore_isolated(
            target, directory, binary=binary / "pg_restore", passwords=passwords()
        )
        assert adopt(source, directory, verify_evidence=attribution)
        assert not adopt(source, directory, verify_evidence=attribution)
        with closing(source.connect()) as conn, conn, conn.cursor() as cur:
            schema.verify(cur)
            cur.execute("SELECT artifacts FROM evidence_pipeline.installation")
            ledger = cur.fetchone()[0]
            assert ledger == schema.artifacts(retained=True)
            cur.execute("SAVEPOINT adopted")
            cur.execute(
                "UPDATE evidence_pipeline.installation SET artifacts=%s",
                (Json(schema.artifacts()),),
            )
            with pytest.raises(ValueError, match="artifact selection"):
                schema.verify(cur)
            cur.execute("ROLLBACK TO SAVEPOINT adopted")
            cur.execute("ALTER ROLE triagemate_test_application BYPASSRLS")
            with pytest.raises(ValueError, match="role authority"):
                schema.verify(cur)
            cur.execute("ROLLBACK TO SAVEPOINT adopted")
            schema.verify(cur)
            # Future migrations must explicitly declare the retained layout and
            # preserve its authority ledger; ordinary contracts cannot waive it.
            from backend.database import migrations

            migration_sql = tmp_path / "future.sql"
            migration_sql.write_text(
                "CREATE VIEW evidence_pipeline.retained_future AS SELECT 1 AS synthetic"
            )
            cur.execute(migration_sql.read_text())
            future_contract = tmp_path / "future-contract.json"
            future_contract.write_text(json.dumps(fingerprint(cur)))
            cur.execute("ROLLBACK TO SAVEPOINT adopted")
            ordinary_contract = schema.BASE / "profiles/runner/current-contract.json"
            monkeypatch.setattr(
                migrations,
                "MIGRATIONS",
                (
                    migrations.Migration(
                        "synthetic-retained-v2", migration_sql, (ordinary_contract,)
                    ),
                ),
            )
            with pytest.raises(ValueError, match="post-state differs"):
                schema.upgrade(cur, database=source.DB)
            cur.execute("ROLLBACK TO SAVEPOINT adopted")
            monkeypatch.setattr(
                migrations,
                "MIGRATIONS",
                (
                    migrations.Migration(
                        "synthetic-retained-v2",
                        migration_sql,
                        (ordinary_contract,),
                        (future_contract,),
                    ),
                ),
            )
            assert schema.upgrade(cur, database=source.DB)
            schema.verify(cur)
            cur.execute("SAVEPOINT future")
            cur.execute(
                "UPDATE evidence_pipeline.installation SET artifacts=%s",
                (Json(schema.artifacts("synthetic-retained-v2")),),
            )
            with pytest.raises(ValueError, match="artifact selection"):
                schema.verify(cur)
            cur.execute("ROLLBACK TO SAVEPOINT future")
            broken = schema.artifacts("synthetic-retained-v2", retained=True)
            broken[retained_runner.PREFIX + "construction.json"] = "0" * 64
            cur.execute(
                "UPDATE evidence_pipeline.installation SET artifacts=%s",
                (Json(broken),),
            )
            with pytest.raises(ValueError, match="artifact or signature"):
                schema.verify(cur)
            cur.execute("ROLLBACK TO SAVEPOINT future")
            assert not schema.upgrade(cur, database=source.DB)


@pytest.mark.parametrize("damage", ["table", "role", "owner"])
def test_restore_preparation_refuses_unrelated_state(monkeypatch, damage):
    with (
        runner_database(monkeypatch) as db,
        closing(db.connect()) as conn,
        conn.cursor() as cur,
    ):
        schema.provision_empty(
            cur, database=db.DB, passwords=passwords(), profile="runner"
        )
        cur.execute(
            {
                "table": "CREATE TABLE public.unrelated(id integer)",
                "role": "CREATE ROLE triagemate_test_application LOGIN",
                "owner": "ALTER SCHEMA public OWNER TO tm_mock_owner",
            }[damage]
        )
        with pytest.raises(ValueError, match="already exist|empty public schema"):
            retained_runner.prepare_isolated_restore(cur)
        cur.execute("SELECT to_regnamespace('public') IS NOT NULL")
        assert cur.fetchone() == (True,)
