"""Connection roles, deadlines and acquisition failures use synthetic secrets."""

import json

import pytest

from backend.database import connections
from backend.database.target import DatabaseTarget


@pytest.fixture(params=["retained", "separate"])
def configured(tmp_path, monkeypatch, request):
    private = tmp_path / "private"
    if request.param == "separate":
        private.mkdir(mode=0o700)
    target = DatabaseTarget(
        work=tmp_path, credentials=private if request.param == "separate" else None
    )
    directory = target.credential_directory
    (directory / "credentials.json").write_text(
        json.dumps({"owner": "synthetic-owner" * 3, "reader": "synthetic-reader" * 3})
    )
    (directory / "credentials.json").chmod(0o600)
    writer = directory / "pipeline-writer.json"
    writer.write_text(json.dumps({"password": "synthetic-writer" * 3}))
    writer.chmod(0o600)
    if request.param == "separate":
        for name, value in {
            "credentials.json": {
                "owner": "wrong-retained-owner" * 3,
                "reader": "wrong-retained-reader" * 3,
            },
            "pipeline-writer.json": {"password": "wrong-retained-writer" * 3},
            "epss-importer.json": {"password": "wrong-retained-importer" * 3},
        }.items():
            decoy = target.work / name
            decoy.write_text(json.dumps(value))
            decoy.chmod(0o600)
    monkeypatch.setattr(connections, "load_target", lambda: target)
    monkeypatch.setattr(connections.psycopg2, "connect", lambda **kwargs: kwargs)
    return target


def test_owner_reader_and_writer_keep_distinct_authority(configured):
    database = connections.local_database()
    owner = database.connect()
    reader = database.connect(reader=True)
    writer = connections.connect_pipeline()
    assert [(c["user"], c["password"]) for c in (owner, reader, writer)] == [
        ("tm_mock_owner", "synthetic-owner" * 3),
        ("tm_mock_reader", "synthetic-reader" * 3),
        ("tm_pipeline_writer", "synthetic-writer" * 3),
    ]
    assert all(c["connect_timeout"] == 5 for c in (owner, reader, writer))
    assert (
        writer["options"]
        == "-c search_path=pg_catalog,evidence,evidence_pipeline -c timezone=UTC -c statement_timeout=20000 -c lock_timeout=10000"
    )
    assert (
        owner["options"]
        == reader["options"]
        == "-c search_path=pg_catalog,evidence,mock_support -c timezone=UTC"
    )


def test_query_reader_retains_async_protocol_and_memory_deadline(configured):
    kwargs = connections.connect_query_reader(
        configured, configured.credential_directory / "credentials.json"
    )
    assert kwargs["user"] == "tm_mock_reader"
    assert kwargs["async_"] is True
    assert kwargs["application_name"] == "triagemate-ui-query"
    assert (
        kwargs["options"]
        == "-c search_path=pg_catalog,evidence,mock_support -c timezone=UTC -c statement_timeout=20000 -c lock_timeout=20000 -c work_mem=32MB"
    )


def test_epss_role_and_settings_are_preserved(configured):
    credential = configured.credential_directory / "epss-importer.json"
    credential.write_text(json.dumps({"password": "synthetic-epss" * 3}))
    credential.chmod(0o600)
    kwargs = connections.connect_epss_importer(configured, credential)
    assert kwargs["user"] == "tm_epss_importer"
    assert kwargs["password"] == "synthetic-epss" * 3
    assert (
        kwargs["options"]
        == "-c search_path=pg_catalog -c timezone=UTC -c statement_timeout=20000 -c lock_timeout=20000"
    )


@pytest.mark.parametrize("damage", ["missing", "permissions", "symlink", "malformed"])
def test_writer_failure_does_not_connect_or_fall_back_to_owner(
    configured, monkeypatch, damage
):
    path = configured.credential_directory / "pipeline-writer.json"
    if damage == "missing":
        path.unlink()
    elif damage == "permissions":
        path.chmod(0o644)
    elif damage == "symlink":
        path.unlink()
        path.symlink_to(configured.credential_directory / "credentials.json")
    else:
        path.write_text("invalid JSON")
    monkeypatch.setattr(
        connections.psycopg2,
        "connect",
        lambda **kwargs: pytest.fail("must reject before connecting"),
    )
    with pytest.raises((OSError, ValueError)):
        connections.connect_pipeline()


def test_handle_resolution_never_reads_credentials_or_connects(configured, monkeypatch):
    from pathlib import Path

    monkeypatch.setattr(
        Path, "read_text", lambda *a, **kw: pytest.fail("must not read secrets")
    )
    monkeypatch.setattr(
        connections.psycopg2, "connect", lambda **kw: pytest.fail("must not connect")
    )
    assert connections.local_database().target == configured


@pytest.mark.parametrize("role", ["owner", "reader", "query", "importer"])
@pytest.mark.parametrize(
    "damage", ["permissions", "symlink", "duplicate", "oversized", "missing_field"]
)
def test_all_connection_roles_reject_unsafe_credentials_before_io(
    configured, monkeypatch, role, damage
):
    path = configured.credential_directory / (
        "epss-importer.json" if role == "importer" else "credentials.json"
    )
    if role == "importer":
        path.write_text(json.dumps({"password": "synthetic-importer" * 3}))
        path.chmod(0o600)
    if damage == "permissions":
        path.chmod(0o644)
    elif damage == "symlink":
        destination = configured.credential_directory / "original-secret"
        path.rename(destination)
        path.symlink_to(destination)
    elif damage == "duplicate":
        key = "password" if role == "importer" else "reader"
        path.write_text(
            '{"' + key + '":"' + "x" * 40 + '","' + key + '":"' + "y" * 40 + '"}'
        )
    elif damage == "oversized":
        path.write_text(" " * 16385)
    else:
        path.write_text("{}")
    monkeypatch.setattr(
        connections.psycopg2,
        "connect",
        lambda **kwargs: pytest.fail("unsafe credential must not reach driver"),
    )
    with pytest.raises((ValueError, OSError)):
        if role == "importer":
            connections.connect_epss_importer(configured, path)
        elif role == "query":
            connections.connect_query_reader(configured, path)
        else:
            connections.local_database().connect(reader=role == "reader")
