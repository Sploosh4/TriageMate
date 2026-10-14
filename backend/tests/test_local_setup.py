"""Local setup uses the complete installer on a disposable synthetic cluster."""

from contextlib import closing
import importlib.util
from pathlib import Path

import pytest

from backend.database.schema import VERSION, verify
from standalone.evidence_pipeline.test_bootstrap import empty_database  # noqa: F401


def test_local_setup_installs_repeats_and_refuses_drift(empty_database, monkeypatch):  # noqa: F811
    path = Path(__file__).resolve().parents[2] / "ui-engine/postgres/manage.py"
    spec = importlib.util.spec_from_file_location("isolated_local_setup", path)
    manage = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(manage)
    # Cluster creation/start are already performed by the disposable fixture.
    # Database setup, all schema installation and connections remain real.
    monkeypatch.setattr(manage, "initialize", lambda: None)
    monkeypatch.setattr(manage, "start", lambda: None)
    database = empty_database
    manage.setup()
    credentials = {p.name: p.read_bytes() for p in database.WORK.glob("*.json")}
    with closing(database.connect()) as conn, conn.cursor() as cur:
        verify(cur)
        cur.execute("SELECT version FROM evidence_pipeline.installation")
        assert cur.fetchone() == (VERSION,)
        cur.execute("SELECT count(*) FROM evidence.source_connections")
        count = cur.fetchone()
        assert count[0] > 0
    manage.setup()
    assert credentials == {p.name: p.read_bytes() for p in database.WORK.glob("*.json")}
    with closing(database.connect()) as conn, conn, conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM evidence.source_connections")
        assert cur.fetchone() == count
        cur.execute("GRANT INSERT ON evidence.source_connections TO tm_mock_reader")
    with pytest.raises(ValueError, match="object_acl"):
        manage.setup()


def test_installed_records_and_credentials_survive_restart(empty_database):  # noqa: F811
    import subprocess

    from backend.database.installation import setup
    from standalone.evidence_pipeline.test_bootstrap import postgres_runtime

    database = empty_database
    setup(database, profile="synthetic")
    root = database.WORK.parent
    _, binary = postgres_runtime()
    credentials = {p.name: p.read_bytes() for p in database.WORK.glob("*.json")}
    with closing(database.connect()) as conn, conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE evidence.organisations SET description='Synthetic restart preservation sentinel' RETURNING id"
        )
        identifiers = cur.fetchall()
        assert identifiers
    subprocess.run(
        [str(binary / "pg_ctl"), "-D", str(root / "pg"), "-m", "fast", "-w", "stop"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            str(binary / "pg_ctl"),
            "-D",
            str(root / "pg"),
            "-l",
            str(root / "server.log"),
            "-o",
            "-k " + str(root / "socket"),
            "-w",
            "start",
        ],
        check=True,
        capture_output=True,
    )
    assert not setup(database, profile="synthetic")
    with closing(database.connect()) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT id FROM evidence.organisations WHERE description='Synthetic restart preservation sentinel'"
        )
        assert set(cur.fetchall()) == set(identifiers)
    assert credentials == {p.name: p.read_bytes() for p in database.WORK.glob("*.json")}
