"""Explicit local CI targets, without connecting or creating infrastructure."""

import json
from pathlib import Path
import pytest

from .database_target import DatabaseTarget, load_target


@pytest.fixture(params=["retained", "separate"])
def config(tmp_path, monkeypatch, request):
    path = tmp_path / "target.json"
    value = {
        "host": str(tmp_path / "socket"),
        "port": 5432,
        "database": "triagemate",
        "work": str(tmp_path / "state"),
    }
    if request.param == "separate":
        value["credentials"] = str(tmp_path / "private")
    path.write_text(json.dumps(value))
    path.chmod(0o600)
    monkeypatch.setenv("TRIAGEMATE_DATABASE_TARGET", str(path))
    return path, value


def test_default_target_is_unchanged(monkeypatch):
    monkeypatch.delenv("TRIAGEMATE_DATABASE_TARGET", raising=False)
    monkeypatch.delenv("TRIAGEMATE_STORAGE_LAYOUT", raising=False)
    assert load_target() == DatabaseTarget()


def test_configured_layout_finds_database_config_without_checkout_paths(
    config, monkeypatch
):
    path, value = config
    expected = load_target()
    directory = path.parent / "application-config"
    directory.mkdir(mode=0o700)
    selected = directory / "database.json"
    selected.write_text(json.dumps(value))
    selected.chmod(0o600)
    monkeypatch.delenv("TRIAGEMATE_DATABASE_TARGET")
    monkeypatch.setenv("TRIAGEMATE_STORAGE_LAYOUT", "configured")
    monkeypatch.setenv("TRIAGEMATE_CONFIG_DIR", str(directory))
    monkeypatch.setenv("TRIAGEMATE_RUNTIME_DIR", str(path.parent / "runtime"))
    assert load_target() == expected
    selected.unlink()
    with pytest.raises(FileNotFoundError):
        load_target()


def test_explicit_target_wins_over_unavailable_configured_default(config, monkeypatch):
    expected = load_target()
    monkeypatch.setenv("TRIAGEMATE_STORAGE_LAYOUT", "configured")
    monkeypatch.setenv(
        "TRIAGEMATE_CONFIG_DIR", "/synthetic-unavailable-application-config"
    )
    assert load_target() == expected


def test_existing_local_socket_target(config):
    path, value = config
    target = load_target()
    assert target.host == value["host"] and target.database == "triagemate"
    assert target.port == 5432 and target.external
    assert not target.work.exists()  # Reading configuration creates nothing.
    assert target.credential_directory == Path(value.get("credentials", value["work"]))
    assert not target.credential_directory.exists()


@pytest.mark.parametrize(
    "value", [None, "", "relative", "/tmp/../private", "/tmp/nul\0"]
)
def test_invalid_credential_directory_cannot_select_legacy(config, value):
    path, data = config
    path.write_text(json.dumps(data | {"credentials": value}))
    with pytest.raises(ValueError, match="Credential directory"):
        load_target()


@pytest.mark.parametrize(
    "damage", ["permissions", "symlink", "ancestor_link", "file", "foreign_owner"]
)
def test_unsafe_explicit_credential_directory_rejected(config, damage, monkeypatch):
    path, data = config
    private = path.parent / "selected-credentials"
    if damage == "file":
        private.write_text("synthetic non-directory")
    elif damage == "symlink":
        private.symlink_to(path.parent, target_is_directory=True)
    elif damage == "ancestor_link":
        parent = path.parent / "parent-link"
        parent.symlink_to(path.parent, target_is_directory=True)
        private = parent / "selected-credentials"
        private.mkdir(mode=0o700)
    elif damage == "foreign_owner":
        import os

        private.mkdir(mode=0o700)
        original_stat = Path.stat

        def changed_owner(candidate, *args, **kwargs):
            info = original_stat(candidate, *args, **kwargs)
            if candidate == private:
                fields = list(info)
                fields[4] = info.st_uid + 1
                return os.stat_result(fields)
            return info

        monkeypatch.setattr(Path, "stat", changed_owner)
    else:
        private.mkdir(mode=0o755)
    path.write_text(json.dumps(data | {"credentials": str(private)}))
    with pytest.raises(ValueError, match="Credential directory"):
        load_target()


@pytest.mark.parametrize(
    "key,value",
    [
        ("host", "remote.example"),
        ("host", "127.0.0.1,remote.example"),
        ("host", "/tmp/socket,remote.example"),
        ("port", True),
        ("port", 0),
        ("database", "triagemate options=unsafe"),
        ("work", "relative"),
        ("password", "must-not-be-here"),
    ],
)
def test_invalid_targets_rejected(config, key, value):
    path, data = config
    data[key] = value
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        load_target()


@pytest.mark.parametrize("damage", ("permissions", "symlink", "duplicate", "oversized"))
def test_unsafe_configuration_file_rejected(config, monkeypatch, damage):
    path, _ = config
    if damage == "permissions":
        path.chmod(0o644)
    elif damage == "symlink":
        link = path.with_name("link.json")
        link.symlink_to(path)
        monkeypatch.setenv("TRIAGEMATE_DATABASE_TARGET", str(link))
    elif damage == "duplicate":
        path.write_text('{"host":"127.0.0.1","host":"127.0.0.1"}')
    else:
        path.write_bytes(b" " * 16385)
    with pytest.raises(ValueError):
        load_target()


def test_lifecycle_and_writer_use_target_without_creating_cluster(config, monkeypatch):
    from . import runtime

    target = load_target()
    for directory in {target.work, target.credential_directory}:
        directory.mkdir(mode=0o700)
    (target.credential_directory / "credentials.json").write_text(
        json.dumps({"owner": "synthetic-owner" * 3, "reader": "synthetic-reader" * 3})
    )
    (target.credential_directory / "credentials.json").chmod(0o600)
    writer = target.credential_directory / "pipeline-writer.json"
    writer.write_text(json.dumps({"password": "synthetic-writer" * 3}))
    writer.chmod(0o600)
    database = runtime.local_database()
    from backend.database import connections

    monkeypatch.setattr(connections.psycopg2, "connect", lambda **kwargs: kwargs)
    for connection in (
        database.connect(),
        database.connect(reader=True),
        runtime.connect(),
    ):
        assert (connection["host"], connection["port"], connection["dbname"]) == (
            target.host,
            target.port,
            target.database,
        )
    database = lifecycle_module()
    with pytest.raises(RuntimeError, match="no new instance"):
        database.initialize()
    with pytest.raises(RuntimeError, match="managed separately"):
        database.native("pg_ctl", "start")
    with pytest.raises(RuntimeError, match="managed separately"):
        database.start()
    assert not database.DATA.exists()


def test_ui_reader_uses_same_explicit_target(config):
    import os
    import subprocess
    import sys
    from .database_target import ROOT

    _, expected = config
    script = "import json; from app.services import postgres_query as p; print(json.dumps([p.TARGET.host,p.TARGET.port,p.TARGET.database,str(p.CONFIG)]))"
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=20,
        env={
            **os.environ,
            "PYTHONPATH": str(ROOT),
        },
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == [
        expected["host"],
        expected["port"],
        expected["database"],
        expected.get("credentials", expected["work"]) + "/credentials.json",
    ]


def test_nonprivate_work_directory_rejected(config):
    from pathlib import Path

    _, value = config
    Path(value["work"]).mkdir(mode=0o755)
    with pytest.raises(ValueError, match="owner-only"):
        load_target()


def test_epss_importer_uses_explicit_target_and_retains_its_role(config):
    import os
    import subprocess
    import sys
    from .database_target import ROOT

    _, expected = config
    state = Path(expected.get("credentials", expected["work"]))
    state.mkdir(mode=0o700)
    (state / "epss-importer.json").write_text(json.dumps({"password": "synthetic" * 5}))
    (state / "epss-importer.json").chmod(0o600)
    script = """import json
from standalone import synthetic_epss_import as importer
importer.psycopg2.connect = lambda **kwargs: {key: value for key, value in kwargs.items() if key != 'password'}
print(json.dumps(importer.connect()))
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=ROOT,
        env=os.environ.copy(),
        capture_output=True,
        text=True,
        timeout=20,
        check=True,
    )
    connection = json.loads(result.stdout)
    assert (
        connection["host"],
        connection["port"],
        connection["dbname"],
        connection["user"],
    ) == (expected["host"], expected["port"], expected["database"], "tm_epss_importer")


def lifecycle_module():
    """Lifecycle tests intentionally exercise the explicit command module."""
    import importlib.util
    from .database_target import ROOT

    spec = importlib.util.spec_from_file_location(
        "test_database_lifecycle", ROOT / "ui-engine/postgres/manage.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_shared_connection_handle_cannot_start_or_install_database(config):
    from backend.database.connections import local_database

    database = local_database()
    for action in ("initialize", "start", "native", "setup", "configure_reader"):
        assert not hasattr(database, action)
