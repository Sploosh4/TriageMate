"""Preparation guards with synthetic local state; no database/service creation."""

import json
from pathlib import Path
from unittest.mock import Mock

import pytest

import ci_evidence_database as setup
from backend.database.target import DatabaseTarget


@pytest.fixture
def ci(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    root = tmp_path / "ci"
    root.mkdir()
    (root / "workspace").write_text(str(setup.ROOT))
    (root / "pg").mkdir()
    (root / "pg/PG_VERSION").write_text("16")
    (root / "socket").mkdir()
    return root


def test_target_is_private_repeatable_and_uses_existing_cluster(ci):
    path, target = setup.paths(ci)
    assert target["database"] == "triagemate"
    assert target["host"] == str(ci / "socket")
    assert target["port"] == 5432
    assert path.stat().st_mode & 0o077 == 0
    assert Path(target["work"]).stat().st_mode & 0o077 == 0
    before = path.stat().st_mtime_ns
    assert setup.paths(ci) == (path, target)
    assert path.stat().st_mtime_ns == before
    assert list((ci / "pg").iterdir()) == [ci / "pg/PG_VERSION"]


@pytest.mark.parametrize(
    "damage", ["github", "workspace", "version", "socket", "state", "target"]
)
def test_wrong_or_redirected_state_is_refused(ci, tmp_path, monkeypatch, damage):
    if damage == "github":
        monkeypatch.setenv("GITHUB_ACTIONS", "true")
    elif damage == "workspace":
        (ci / "workspace").write_text("/wrong/check/out")
    elif damage == "version":
        (ci / "pg/PG_VERSION").write_text("17")
    elif damage in {"socket", "state"}:
        name = "socket" if damage == "socket" else "ui-postgresql"
        if (ci / name).exists():
            (ci / name).rmdir()
        (ci / name).symlink_to(tmp_path)
    else:
        path, target = setup.paths(ci)
        target["database"] = "another"
        path.write_text(json.dumps(target))
    with pytest.raises(ValueError):
        setup.paths(ci)


def test_prepared_credentials_are_reused_and_never_overwritten(tmp_path):
    path = tmp_path / "credentials.json"
    assert setup.private_json(path, {"password": "synthetic"}) == {
        "password": "synthetic"
    }
    assert setup.private_json(path, {"password": "different"}) == {
        "password": "synthetic"
    }
    path.chmod(0o644)
    with pytest.raises(ValueError, match="owner-only"):
        setup.private_json(path)


def test_credential_symlink_and_missing_credentials_are_refused(tmp_path):
    path = tmp_path / "credentials.json"
    with pytest.raises(ValueError, match="no local credentials"):
        setup.private_json(path)
    original = tmp_path / "original"
    original.write_text("{}")
    path.symlink_to(original)
    with pytest.raises(OSError):
        setup.private_json(path, {})
    assert original.read_text() == "{}"


class Cursor:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.statements = []

    def execute(self, statement, parameters=None):
        self.statements.append(statement)

    def fetchone(self):
        return next(self.responses)

    def fetchall(self):
        return next(self.responses)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


class Connection:
    def __init__(self, cursor):
        self.value = cursor

    def cursor(self):
        return self.value

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def __enter__(self):
        if getattr(self, "entered", False):
            raise RuntimeError("connection cannot be re-entered recursively")
        self.entered = True
        return self

    def __exit__(self, *args):
        self.entered = False


def database(ci):
    _, target = setup.paths(ci)
    return setup.LocalDatabase(
        DatabaseTarget(**{**target, "work": Path(target["work"])}, external=True)
    )


@pytest.mark.parametrize("wrong", ["database", "user", "cluster"])
def test_connection_identity_is_checked_before_mutation(ci, wrong):
    identity = ["triagemate", "triagemate", str(ci / "pg")]
    identity[["database", "user", "cluster"].index(wrong)] = "wrong"
    cursor = Cursor([tuple(identity)])
    with pytest.raises(ValueError, match="not the retained"):
        setup.seed(Connection(cursor), database(ci), ci)
    assert all(statement.startswith("SELECT") for statement in cursor.statements)


@pytest.mark.parametrize(
    "schemas,manifest,roles",
    [
        ([], "unknown", []),
        ([], None, [("tm_mock_owner",)]),
    ],
)
def test_unknown_schema_annotation_or_roles_are_not_replaced(
    ci, schemas, manifest, roles
):
    cursor = Cursor(
        [("triagemate", "triagemate", str(ci / "pg")), (manifest,), schemas, roles]
    )
    with pytest.raises(ValueError):
        setup.seed(Connection(cursor), database(ci), ci)
    assert all(statement.startswith("SELECT") for statement in cursor.statements)


def test_seed_delegates_runner_baseline_in_same_transaction(ci, monkeypatch):
    cursor = Cursor([("triagemate", "triagemate", str(ci / "pg")), (None,), [], []])
    db = database(ci)
    passwords = object()
    prepare = Mock(return_value=passwords)
    install = Mock()
    monkeypatch.setattr(setup, "prepare_passwords", prepare)
    monkeypatch.setattr(setup, "install", install)
    conn = Connection(cursor)
    assert setup.seed(conn, db, ci)
    prepare.assert_called_once_with(db, cursor)
    install.assert_called_once_with(
        cursor, database="triagemate", passwords=passwords, profile="runner"
    )
    assert conn.committed
    assert not any("CREATE DATABASE" in s or "DROP" in s for s in cursor.statements)
    assert (db.WORK / "credentials.json").stat().st_mode & 0o077 == 0


@pytest.mark.parametrize("invalid", [False, True])
def test_existing_schema_requires_complete_verification_before_upgrade(
    ci, monkeypatch, invalid
):
    cursor = Cursor(
        [("triagemate", "triagemate", str(ci / "pg")), ("annotation",), [("evidence",)]]
    )
    db = database(ci)
    setup.private_json(
        db.WORK / "credentials.json", {"owner": "x" * 32, "reader": "y" * 32}
    )
    verify = Mock(
        side_effect=ValueError("Unsupported database version") if invalid else None
    )
    upgrade = Mock()
    install = Mock()
    monkeypatch.setattr(setup, "verify", verify)
    monkeypatch.setattr(setup, "upgrade", upgrade)
    monkeypatch.setattr(setup, "install", install)
    conn = Connection(cursor)
    if invalid:
        with pytest.raises(ValueError, match="Unsupported database version"):
            setup.seed(conn, db, ci)
        upgrade.assert_not_called()
        assert conn.rolled_back
    else:
        assert not setup.seed(conn, db, ci)
        upgrade.assert_called_once_with(cursor, database="triagemate")
        assert conn.committed
    verify.assert_called_once_with(cursor, require_latest=False)
    install.assert_not_called()


def test_preparation_cannot_overlap_another_ci_operation(ci):
    with setup.operation_lock(ci):
        with pytest.raises(BlockingIOError):
            with setup.operation_lock(ci):
                pytest.fail("Acquired an already held operation lock")
    with setup.operation_lock(ci):
        pass


def test_preparation_does_not_follow_a_redirected_lock(ci, tmp_path):
    outside = tmp_path / "outside"
    outside.write_text("keep")
    (ci / "operation.lock").symlink_to(outside)
    with pytest.raises(OSError):
        with setup.operation_lock(ci):
            pytest.fail("Followed a lock symlink")
    assert outside.read_text() == "keep"


def test_preparation_rejects_redirected_database_directory(ci, tmp_path):
    (ci / "pg/PG_VERSION").unlink()
    (ci / "pg").rmdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "PG_VERSION").write_text("16")
    (ci / "pg").symlink_to(outside)
    with pytest.raises(ValueError, match="must not be a symlink"):
        setup.paths(ci)


def test_fixture_failure_rolls_back_role_preparation(ci, monkeypatch):
    cursor = Cursor([("triagemate", "triagemate", str(ci / "pg")), (None,), [], []])
    monkeypatch.setattr(setup, "prepare_passwords", Mock(return_value=object()))
    monkeypatch.setattr(
        setup, "install", Mock(side_effect=RuntimeError("synthetic fixture failure"))
    )
    conn = Connection(cursor)
    with pytest.raises(RuntimeError, match="fixture failure"):
        setup.seed(conn, database(ci), ci)
    assert conn.rolled_back
    assert not getattr(conn, "committed", False)


def test_real_runner_profile_setup_repeat_and_legacy_refusal(monkeypatch):
    """The runner's authority profile is reproduced in a disposable cluster."""
    from contextlib import closing
    import psycopg2

    from backend.database.baseline.catalogue import fingerprint
    from backend.database.baseline.profiles import identify_layout
    from backend.database.credentials import read_credentials
    from standalone.evidence_pipeline.test_bootstrap import isolated_database

    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    with isolated_database(
        monkeypatch, owner="triagemate", name="triagemate"
    ) as original:
        root = original.WORK.parent
        (root / "workspace").write_text(str(setup.ROOT))
        _, target = setup.paths(root)
        db = setup.LocalDatabase(
            DatabaseTarget(**{**target, "work": Path(target["work"])}, external=True)
        )
        password = read_credentials(
            original.WORK / "credentials.json", frozenset({"owner", "reader"})
        )["owner"]
        with closing(
            psycopg2.connect(
                host=target["host"],
                port=5432,
                dbname="triagemate",
                user="triagemate",
                password=password,
            )
        ) as conn:
            assert setup.seed(conn, db, root)
            with conn, conn.cursor() as cur:
                assert identify_layout(fingerprint(cur)) == ("runner", False)
            assert not setup.seed(conn, db, root)
            assert not setup.verify_logins(db, profile="runner")
            with conn, conn.cursor() as cur:
                cur.execute(
                    "UPDATE evidence_pipeline.installation SET version='pipeline-windows-os-native-facts-v113'"
                )
            with pytest.raises(ValueError, match="Unsupported database version"):
                setup.seed(conn, db, root)
            with conn.cursor() as cur:
                cur.execute("SELECT version FROM evidence_pipeline.installation")
                assert cur.fetchone() == ("pipeline-windows-os-native-facts-v113",)
