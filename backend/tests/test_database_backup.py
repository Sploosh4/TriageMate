"""Synthetic backup/restore evidence; no development target or remote access."""

from contextlib import closing
import json
import secrets
import shutil

import pytest

from backend.database.backup import capture, restore_isolated
from backend.database.schema import InstallPasswords, install, verify
from standalone.evidence_pipeline.test_bootstrap import empty_database  # noqa: F401
from standalone.evidence_pipeline.test_bootstrap import postgres_runtime


@pytest.fixture
def isolated_restore(monkeypatch):
    yield from empty_database.__wrapped__(monkeypatch)


def credentials():
    return InstallPasswords(*(secrets.token_urlsafe(32) for _ in range(3)))


def binary(name):
    # Use the same versioned installation as these isolated test clusters.
    # Resolving Debian's /usr/bin/pg_dump symlink selects pg_wrapper itself and
    # loses the utility name required by both the wrapper and backup contract.
    return postgres_runtime()[1] / name


def test_backup_restores_rows_metadata_and_authority(
    empty_database, isolated_restore, tmp_path
):  # noqa: F811
    source, target = empty_database, isolated_restore
    with closing(source.connect()) as conn, conn, conn.cursor() as cur:
        install(cur, database=source.DB, passwords=credentials())
        cur.execute(
            "INSERT INTO evidence.source_connections(id,source_name,input_kind,scope_reference) SELECT gen_random_uuid(),'FIRST','epss','explicit synthetic backup test '||n FROM generate_series(1,2001) n"
        )
    parent = tmp_path / "backups"
    parent.mkdir(mode=0o700)
    directory = parent / "synthetic"
    receipt_path = capture(source, directory, binary=binary("pg_dump"))
    receipt = json.loads(receipt_path.read_text())
    assert receipt["rows"]["evidence.source_connections"]["rows"] == 2001
    assert "explicit synthetic backup test" not in receipt_path.read_text()
    assert directory.stat().st_mode & 0o777 == 0o700
    for path in directory.iterdir():
        assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        capture(source, directory, binary=binary("pg_dump"))
    with pytest.raises(ValueError, match="different isolated"):
        restore_isolated(
            source, directory, binary=binary("pg_restore"), passwords=credentials()
        )
    result = restore_isolated(
        target, directory, binary=binary("pg_restore"), passwords=credentials()
    )
    assert json.loads(result.read_text())["verified"] is True
    with closing(target.connect()) as conn, conn.cursor() as cur:
        verify(cur)
        cur.execute("SELECT count(*) FROM evidence.source_connections")
        assert cur.fetchone() == (2001,)
    with closing(source.connect()) as conn, conn.cursor() as cur:
        verify(cur)
        cur.execute("SELECT count(*) FROM evidence.source_connections")
        assert cur.fetchone() == (2001,)
    # Corrupt the independently owned synthetic copy, never a real backup.
    damaged = parent / "damaged"
    shutil.copytree(directory, damaged)
    with (damaged / "database.dump").open("ab") as stream:
        stream.write(b"synthetic corruption")
    with pytest.raises(ValueError, match="digest differs"):
        restore_isolated(
            target, damaged, binary=binary("pg_restore"), passwords=credentials()
        )


@pytest.mark.parametrize("damage", ["public", "symlink"])
def test_backup_refuses_unsafe_parent_before_connection(tmp_path, damage):
    from types import SimpleNamespace

    parent = tmp_path / "parent"
    parent.mkdir(mode=0o700)
    if damage == "public":
        parent.chmod(0o755)
    else:
        link = tmp_path / "link"
        link.symlink_to(parent, target_is_directory=True)
        parent = link
    with pytest.raises(ValueError, match="0700|symlink"):
        capture(SimpleNamespace(), parent / "backup", binary=binary("pg_dump"))
    assert not (parent / "backup").exists()


def test_verified_predecessor_adoption_changes_only_metadata(
    empty_database, isolated_restore, tmp_path, monkeypatch
):
    from backend.database.adoption import adopt
    from backend.database.backup import sequence_receipt
    from backend.database.baseline.evidence import evidence_receipt
    from backend.database.schema import VERSION
    from standalone.evidence_pipeline.test_attribution import verify as verify_evidence

    source = empty_database
    from backend.tests.predecessor_fixture import restore_predecessor

    restore_predecessor(source, tmp_path)
    parent = tmp_path / "backups"
    parent.mkdir(mode=0o700)
    directory = parent / "predecessor"
    capture(source, directory, binary=binary("pg_dump"))
    with pytest.raises(FileNotFoundError):
        adopt(source, directory, verify_evidence=verify_evidence)
    restore_isolated(
        isolated_restore,
        directory,
        binary=binary("pg_restore"),
        passwords=credentials(),
    )

    def reject_evidence(cur):
        raise ValueError("synthetic attribution rejection")

    with pytest.raises(ValueError, match="attribution rejection"):
        adopt(source, directory, verify_evidence=reject_evidence)
    with closing(source.connect()) as conn, conn, conn.cursor() as cur:
        cur.execute("COMMENT ON DATABASE empty_test IS 'synthetic changed annotation'")
    with pytest.raises(ValueError, match="annotation changed|annotation differs"):
        adopt(source, directory, verify_evidence=verify_evidence)
    receipt = json.loads((directory / "receipt.json").read_text())
    with closing(source.connect()) as conn, conn, conn.cursor() as cur:
        cur.execute("COMMENT ON DATABASE empty_test IS %s", (receipt["annotation"],))
        cur.execute("SELECT nextval('evidence_pipeline.operation_events_id_seq')")
    with pytest.raises(ValueError, match="Evidence changed since backup"):
        adopt(source, directory, verify_evidence=verify_evidence)
    with closing(source.connect()) as conn, conn, conn.cursor() as cur:
        # Reset only the deliberately advanced sequence in this disposable
        # synthetic test cluster to its captured state before the positive case.
        state = receipt["sequences"]["evidence_pipeline.operation_events_id_seq"]
        cur.execute(
            "SELECT setval('evidence_pipeline.operation_events_id_seq',%s,%s)", state
        )
    assert adopt(source, directory, verify_evidence=verify_evidence)
    assert not adopt(source, directory, verify_evidence=verify_evidence)
    receipt = json.loads((directory / "receipt.json").read_text())
    with closing(source.connect()) as conn:
        conn.set_session(isolation_level="REPEATABLE READ", readonly=True)
        with conn.cursor() as cur:
            verify(cur)
            assert evidence_receipt(cur) == receipt["rows"]
            assert sequence_receipt(cur) == receipt["sequences"]
            cur.execute("SELECT version FROM evidence_pipeline.installation")
            assert cur.fetchone() == (VERSION,)


@pytest.mark.parametrize(
    "damage",
    [None, "row", "schema", "annotation", "metadata", "archive", "receipt", "source"],
)
def test_interrupted_restore_verification_resumes_without_reimport(
    empty_database, isolated_restore, tmp_path, monkeypatch, damage
):
    from backend.database import backup
    from psycopg2 import sql

    source, target = empty_database, isolated_restore
    with closing(source.connect()) as conn, conn, conn.cursor() as cur:
        install(cur, database=source.DB, passwords=credentials())
    parent = tmp_path / "resume-backups"
    parent.mkdir(mode=0o700)
    directory = parent / "synthetic"
    capture(source, directory, binary=binary("pg_dump"))
    original = backup.evidence_receipt

    def interrupted(cur):
        raise OSError("synthetic scratch exhaustion after restore")

    with monkeypatch.context() as patch:
        patch.setattr(backup, "evidence_receipt", interrupted)
        with pytest.raises(OSError, match="synthetic scratch"):
            restore_isolated(
                target, directory, binary=binary("pg_restore"), passwords=credentials()
            )
    assert (directory / "restore.log").exists()
    assert not (directory / "restore.json").exists()
    if damage in {"row", "schema", "annotation", "metadata"}:
        with closing(target.connect()) as conn, conn, conn.cursor() as cur:
            if damage == "row":
                cur.execute(
                    "INSERT INTO evidence.source_connections(id,source_name,input_kind,scope_reference) VALUES(gen_random_uuid(),'FIRST','epss','synthetic unexpected restored row')"
                )
            elif damage == "schema":
                cur.execute(
                    "CREATE TABLE public.unexpected_synthetic_table (value integer)"
                )
            elif damage == "annotation":
                cur.execute(
                    sql.SQL(
                        "COMMENT ON DATABASE {} IS 'synthetic changed annotation'"
                    ).format(sql.Identifier(target.DB))
                )
            else:
                cur.execute(
                    "UPDATE evidence_pipeline.installation SET version='synthetic-changed'"
                )
    elif damage == "archive":
        with (directory / "database.dump").open("ab") as stream:
            stream.write(b"synthetic damage")
    elif damage == "receipt":

        def changed_receipt(cur):
            result = original(cur)
            path = directory / "receipt.json"
            path.write_bytes(path.read_bytes() + b"\n")
            return result

        monkeypatch.setattr(backup, "evidence_receipt", changed_receipt)
    if damage:
        with pytest.raises(ValueError):
            backup.verify_restored(source if damage == "source" else target, directory)
        assert not (directory / "restore.json").exists()
    else:
        proof = backup.verify_restored(target, directory)
        assert json.loads(proof.read_text())["verified"] is True
        with pytest.raises(ValueError, match="already exists"):
            backup.verify_restored(target, directory)
    with closing(source.connect()) as conn, conn.cursor() as cur:
        verify(cur)
        cur.execute("SELECT count(*) FROM evidence.source_connections")
        assert cur.fetchone() == (0,)
