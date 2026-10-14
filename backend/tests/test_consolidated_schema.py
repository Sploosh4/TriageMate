"""Consolidated installation on explicitly isolated synthetic PostgreSQL targets."""

from contextlib import closing
import secrets

import pytest

from backend.database.schema import InstallPasswords, VERSION, install, verify
from standalone.evidence_pipeline.test_bootstrap import empty_database  # noqa: F401


def passwords():
    return InstallPasswords(*(secrets.token_urlsafe(32) for _ in range(3)))


@pytest.mark.parametrize("profile", ["empty", "synthetic"])
def test_fresh_install_repeat_and_drift_refusal(empty_database, profile):  # noqa: F811
    database = empty_database
    credentials = passwords()
    from standalone.evidence_pipeline.test_attribution import verify as verify_evidence

    with closing(database.connect()) as conn, conn, conn.cursor() as cur:
        assert install(
            cur, database=database.DB, passwords=credentials, profile=profile
        )
        verify(cur)
        verify_evidence(cur)
        with pytest.raises(ValueError, match="profile differs"):
            install(
                cur,
                database=database.DB,
                passwords=credentials,
                profile="synthetic" if profile == "empty" else "empty",
            )
        cur.execute("SELECT version FROM evidence_pipeline.installation")
        assert cur.fetchone() == (VERSION,)
        cur.execute(
            "SELECT rolpassword FROM pg_authid WHERE rolname='tm_pipeline_writer'"
        )
        writer_hash = cur.fetchone()
        assert not install(
            cur, database=database.DB, passwords=passwords(), profile=profile
        )
        cur.execute(
            "SELECT rolpassword FROM pg_authid WHERE rolname='tm_pipeline_writer'"
        )
        assert cur.fetchone() == writer_hash
        cur.execute("SAVEPOINT valid")
        cur.execute("GRANT INSERT ON evidence.source_connections TO tm_mock_reader")
        with pytest.raises(ValueError, match="object_acl"):
            verify(cur)
        cur.execute("ROLLBACK TO SAVEPOINT valid")
        cur.execute("UPDATE evidence_pipeline.installation SET version='unknown'")
        with pytest.raises(ValueError, match="Unsupported database version"):
            install(cur, database=database.DB, passwords=credentials, profile=profile)
        cur.execute("ROLLBACK TO SAVEPOINT valid")
        verify(cur)


@pytest.mark.parametrize(
    "existing", ["schema", "table", "function", "type", "role", "annotation"]
)
def test_install_rejects_existing_state_without_mutation(empty_database, existing):  # noqa: F811
    database = empty_database
    statement = {
        "schema": "CREATE SCHEMA unrelated",
        "table": "CREATE TABLE public.unrelated(id integer)",
        "function": "CREATE FUNCTION public.unrelated() RETURNS integer LANGUAGE sql AS 'SELECT 1'",
        "type": "CREATE TYPE public.unrelated AS ENUM('a')",
        "role": "CREATE ROLE tm_pipeline_writer NOLOGIN",
        "annotation": "COMMENT ON DATABASE empty_test IS 'unrelated installation'",
    }[existing]
    with closing(database.connect()) as conn, conn.cursor() as cur:
        cur.execute(statement)
        with pytest.raises(ValueError, match="existing|already|Reserved"):
            install(cur, database=database.DB, passwords=passwords())
        cur.execute("SELECT to_regnamespace('evidence')")
        assert cur.fetchone() == (None,)
        cur.execute("SELECT 1 FROM pg_roles WHERE rolname='tm_mock_reader'")
        assert cur.fetchone() is None


def test_install_does_not_commit(empty_database):  # noqa: F811
    database = empty_database
    with closing(database.connect()) as conn, conn.cursor() as cur:
        install(cur, database=database.DB, passwords=passwords())
        conn.rollback()
        cur.execute("SELECT to_regnamespace('evidence')")
        assert cur.fetchone() == (None,)
        cur.execute("SELECT 1 FROM pg_roles WHERE rolname='tm_mock_reader'")
        assert cur.fetchone() is None


def test_install_passwords_reject_weak_or_shared_secrets():
    with pytest.raises(ValueError, match="at least 32"):
        InstallPasswords("short", "x" * 32, "y" * 32).validated()
    with pytest.raises(ValueError, match="distinct"):
        InstallPasswords("x" * 32, "x" * 32, "y" * 32).validated()


def test_future_migrations_are_ordered_verified_and_atomic(
    empty_database,  # noqa: F811
    tmp_path,
    monkeypatch,
):  # noqa: F811
    import json
    from backend.database import migrations
    from backend.database.baseline.catalogue import fingerprint
    from backend.database.schema import latest_version, upgrade

    database = empty_database
    with closing(database.connect()) as conn, conn.cursor() as cur:
        install(cur, database=database.DB, passwords=passwords())
        conn.commit()
        source = tmp_path / "future.sql"
        source.write_text(
            "CREATE VIEW evidence_pipeline.future_test AS SELECT 1 AS synthetic_value"
        )
        contract_path = tmp_path / "future-contract.json"
        # A synthetic future revision constructed independently in a savepoint.
        cur.execute("SAVEPOINT candidate")
        cur.execute(source.read_text())
        contract_path.write_text(json.dumps(fingerprint(cur)))
        second_source = tmp_path / "second.sql"
        second_source.write_text(
            "CREATE VIEW evidence_pipeline.future_second AS SELECT synthetic_value FROM evidence_pipeline.future_test"
        )
        cur.execute(second_source.read_text())
        second_contract = tmp_path / "second-contract.json"
        second_contract.write_text(json.dumps(fingerprint(cur)))
        cur.execute("ROLLBACK TO SAVEPOINT candidate")
        revision = migrations.Migration("synthetic-future-v2", source, (contract_path,))
        monkeypatch.setattr(
            migrations,
            "MIGRATIONS",
            (
                revision,
                migrations.Migration(
                    "synthetic-future-v3", second_source, (second_contract,)
                ),
            ),
        )
        with pytest.raises(ValueError, match="Unsupported database version"):
            verify(cur)
        assert latest_version() == "synthetic-future-v3"
        assert upgrade(cur, database=database.DB)
        verify(cur)
        assert not upgrade(cur, database=database.DB)
        original_sql = source.read_text()
        source.write_text(original_sql + "; -- changed prior artifact")
        with pytest.raises(ValueError, match="artifact or signature metadata"):
            verify(cur)
        source.write_text(original_sql)
        cur.execute("SELECT synthetic_value FROM evidence_pipeline.future_test")
        assert cur.fetchone() == (1,)
        conn.rollback()
        cur.execute("SELECT version FROM evidence_pipeline.installation")
        assert cur.fetchone() == (VERSION,)
        cur.execute("SELECT to_regclass('evidence_pipeline.future_test')")
        assert cur.fetchone() == (None,)
        source.write_text(
            "CREATE VIEW evidence_pipeline.future_test AS SELECT 2 AS synthetic_value"
        )
        with pytest.raises(ValueError, match="post-state differs"):
            upgrade(cur, database=database.DB)
        conn.rollback()
        cur.execute("SELECT version FROM evidence_pipeline.installation")
        assert cur.fetchone() == (VERSION,)
        cur.execute("SELECT to_regclass('evidence_pipeline.future_test')")
        assert cur.fetchone() == (None,)


def test_future_registry_rejects_duplicates_and_unverified_revisions(
    tmp_path, monkeypatch
):
    from backend.database import migrations

    revision = migrations.Migration(
        "future-v2", tmp_path / "change.sql", (tmp_path / "contract.json",)
    )
    monkeypatch.setattr(migrations, "MIGRATIONS", (revision, revision))
    with pytest.raises(ValueError, match="unique"):
        migrations.revisions()
    monkeypatch.setattr(
        migrations,
        "MIGRATIONS",
        (migrations.Migration("future-v2", revision.source, ()),),
    )
    with pytest.raises(ValueError, match="trusted schema contracts"):
        migrations.revisions()


def test_shared_setup_registration_and_restricted_ingestion(empty_database):  # noqa: F811
    from backend.database.installation import setup
    from backend.database.connections import connect_pipeline
    from standalone.evidence_pipeline.commands import register
    from standalone.evidence_pipeline.persistence.public_store import persist_public
    from standalone.evidence_pipeline.test_public_snapshot import attempt
    from standalone.evidence_pipeline.test_attribution import verify as verify_evidence
    from backend.database.credentials import read_credentials

    database = empty_database
    assert setup(database)
    original = read_credentials(
        database.WORK / "pipeline-writer.json", frozenset({"password"})
    )
    assert not setup(database)
    assert (
        read_credentials(
            database.WORK / "pipeline-writer.json", frozenset({"password"})
        )
        == original
    )
    snapshot = attempt()
    assert register(snapshot.scope)
    assert not register(snapshot.scope)
    with closing(connect_pipeline()) as conn, conn:
        from standalone.evidence_pipeline.persistence.store import (
            require_input_migration,
        )

        with conn.cursor() as cur:
            for feature in ("update-status", "antivirus", "catalogue"):
                require_input_migration(cur, feature)
        assert not persist_public(conn, snapshot)["replayed"]
        assert persist_public(conn, snapshot)["replayed"]
    with closing(database.connect()) as conn, conn.cursor() as cur:
        assert verify_evidence(cur)["epss_observations"] == 1


def test_every_preserved_reference_file_is_bound_to_installation(
    empty_database,  # noqa: F811
    monkeypatch,
):
    import hashlib
    import json
    from pathlib import Path

    from backend.database import schema

    original = json.loads((schema.BASE / "construction.json").read_text())[
        "predecessor_artifacts"
    ]
    names = [name for name in original if name.endswith(".json")]
    assert len(names) == 15
    database = empty_database
    with closing(database.connect()) as conn, conn, conn.cursor() as cur:
        assert install(cur, database=database.DB, passwords=passwords())
        for name in names:
            target = schema.BASE / "references" / name
            assert hashlib.sha256(target.read_bytes()).hexdigest() == original[name]
            assert "references/" + name in schema.artifacts()
            read = Path.read_bytes

            def changed(path, *args, **kwargs):
                raw = read(path, *args, **kwargs)
                return raw + b"\n" if path == target else raw

            with monkeypatch.context() as patch:
                patch.setattr(Path, "read_bytes", changed)
                with pytest.raises(
                    ValueError, match="artifact or signature metadata differs"
                ):
                    verify(cur)
        verify(cur)
