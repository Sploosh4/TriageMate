"""Container refusal preserves an unrelated database, including its grants."""

from contextlib import closing
import os
from pathlib import Path

import pytest

from app import bootstrap
from backend.database.credentials import read_credentials
from standalone.evidence_pipeline.test_bootstrap import isolated_database


@pytest.fixture
def preserve_umask():
    previous = os.umask(0o077)
    os.umask(previous)
    try:
        yield
    finally:
        os.umask(previous)


def test_bootstrap_rejects_unknown_database_without_changing_grants(
    monkeypatch, tmp_path, preserve_umask
):
    with isolated_database(monkeypatch, name="triagemate") as database:
        with closing(database.connect()) as conn, conn, conn.cursor() as cur:
            cur.execute("CREATE TABLE public.unrelated(id integer)")
            cur.execute("INSERT INTO public.unrelated VALUES (42)")
            cur.execute(
                "SELECT datacl FROM pg_database WHERE datname=%s", (database.DB,)
            )
            original_acl = cur.fetchone()
        root = tmp_path / "application"
        monkeypatch.setattr(bootstrap, "Path", lambda _path: Path(root))
        monkeypatch.setattr(bootstrap, "load_target", lambda: database.target)
        monkeypatch.setattr(bootstrap, "LocalDatabase", lambda _target: database)
        owner = read_credentials(
            database.CREDENTIALS / "credentials.json", frozenset({"owner", "reader"})
        )["owner"]
        monkeypatch.setenv("TRIAGEMATE_DB_OWNER_PASSWORD", owner)
        with pytest.raises(ValueError, match="existing|already"):
            bootstrap.main()
        with closing(database.connect()) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT datacl FROM pg_database WHERE datname=%s", (database.DB,)
            )
            assert cur.fetchone() == original_acl
            cur.execute("SELECT id FROM public.unrelated")
            assert cur.fetchall() == [(42,)]
            cur.execute("SELECT to_regnamespace('evidence')")
            assert cur.fetchone() == (None,)
