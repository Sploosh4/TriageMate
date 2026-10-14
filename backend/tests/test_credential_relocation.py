"""Private credential copies reconnect to the same synthetic database and roles."""

from contextlib import closing
import json
import os
from pathlib import Path

import pytest
from psycopg2.extras import wait_select

from backend.configuration.storage_copy import copy_tree_verified
from backend.database.connections import (
    connect_epss_importer,
    connect_pipeline,
    connect_query_reader,
    local_database,
)
from backend.database.installation import setup
from backend.database.schema import verify
from standalone.evidence_pipeline.test_bootstrap import empty_database as empty_database


@pytest.mark.parametrize("selection", ["explicit", "configured"])
def test_copied_credentials_preserve_database_identity_roles_and_originals(
    empty_database, tmp_path, monkeypatch, selection
):
    original = empty_database
    setup(original, profile="synthetic")
    before = {path.name: path.read_bytes() for path in original.CREDENTIALS.iterdir()}
    assert set(before) == {
        "credentials.json",
        "pipeline-writer.json",
        "epss-importer.json",
    }
    with closing(original.connect()) as conn, conn.cursor() as cursor:
        cursor.execute("SELECT current_database(), current_setting('data_directory')")
        identity = cursor.fetchone()
        cursor.execute("SELECT count(*) FROM evidence.source_connections")
        count = cursor.fetchone()

    config = tmp_path / "config"
    config.mkdir(mode=0o700)
    selected = config / "credentials"
    copied = copy_tree_verified(original.CREDENTIALS, selected)
    assert len(copied.files) == 3
    target_path = Path(os.environ["TRIAGEMATE_DATABASE_TARGET"])
    original_target = target_path.read_bytes()
    new_target = config / "database.json"
    new_target.write_text(
        json.dumps(json.loads(original_target) | {"credentials": str(selected)})
    )
    new_target.chmod(0o600)
    if selection == "explicit":
        monkeypatch.setenv("TRIAGEMATE_DATABASE_TARGET", str(new_target))
    else:
        monkeypatch.delenv("TRIAGEMATE_DATABASE_TARGET")
        monkeypatch.setenv("TRIAGEMATE_STORAGE_LAYOUT", "configured")
        monkeypatch.setenv("TRIAGEMATE_CONFIG_DIR", str(config))
        monkeypatch.setenv("TRIAGEMATE_RUNTIME_DIR", str(tmp_path / "runtime"))
    relocated = local_database()
    assert relocated.WORK == original.WORK
    assert relocated.CREDENTIALS == selected
    assert setup(relocated, profile="synthetic") is False
    assert {path.name: path.read_bytes() for path in selected.iterdir()} == before
    assert {
        path.name: path.read_bytes() for path in original.CREDENTIALS.iterdir()
    } == before
    assert target_path.read_bytes() == original_target
    with closing(relocated.connect()) as conn, conn.cursor() as cursor:
        verify(cursor)
        cursor.execute("SELECT current_database(), current_setting('data_directory')")
        assert cursor.fetchone() == identity
        cursor.execute("SELECT count(*) FROM evidence.source_connections")
        assert cursor.fetchone() == count
    connections = [
        (lambda: relocated.connect(), "tm_mock_owner"),
        (lambda: relocated.connect(reader=True), "tm_mock_reader"),
        (connect_pipeline, "tm_pipeline_writer"),
        (
            lambda: connect_epss_importer(
                relocated.TARGET, selected / "epss-importer.json"
            ),
            "tm_epss_importer",
        ),
    ]
    for connect, expected_role in connections:
        with closing(connect()) as conn, conn.cursor() as cursor:
            cursor.execute("SELECT current_user")
            assert cursor.fetchone() == (expected_role,)
    with closing(
        connect_query_reader(relocated.TARGET, selected / "credentials.json")
    ) as conn:
        wait_select(conn)
        with conn.cursor() as cursor:
            cursor.execute("SELECT current_user")
            wait_select(conn)
            assert cursor.fetchone() == ("tm_mock_reader",)

    # An intact old credential is not a fallback after selecting a new directory.
    (selected / "pipeline-writer.json").unlink()
    with pytest.raises(FileNotFoundError):
        connect_pipeline()
    assert (original.CREDENTIALS / "pipeline-writer.json").read_bytes() == before[
        "pipeline-writer.json"
    ]
