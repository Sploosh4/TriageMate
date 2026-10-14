"""Saved-file identity and streaming writes preserve atomic source evidence."""

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
from uuid import uuid4

import pytest

from .file_payload import FilePayload
from standalone.evidence_pipeline.parsing.public_snapshot import PublicSnapshot
from standalone.evidence_pipeline.parsing.public_records import normalize_public
from .test_debian_tracker import document, scope
from .test_store import db as database_fixture
from standalone.evidence_pipeline.persistence.authority import authorize_connection
from standalone.evidence_pipeline.persistence.public_store import persist_public

db = database_fixture


def saved(tmp_path, raw):
    path = tmp_path / "payload.bin"
    path.write_bytes(raw)
    path.chmod(0o600)
    return FilePayload(path, hashlib.sha256(raw).hexdigest())


def snapshot(tmp_path, raw=None):
    raw = json.dumps(document()).encode() if raw is None else raw
    now = datetime.now(timezone.utc)
    return PublicSnapshot(
        scope(), str(uuid4()), now, now, "success", True, saved(tmp_path, raw)
    )


def test_streamed_normalization_is_identical_to_existing_bytes(tmp_path):
    raw = json.dumps(document()).encode()
    value = snapshot(tmp_path, raw)
    ordinary = replace(value, payload=raw)
    assert list(normalize_public(value.feed())) == list(
        normalize_public(ordinary.feed())
    )
    assert (
        value.input_fingerprint
        == value.feed().input_fingerprint
        == ordinary.input_fingerprint
    )


@pytest.mark.parametrize(
    "damage", ["changed", "public", "symlink", "wrong_hash", "truncated"]
)
def test_saved_payload_validation_fails_closed(tmp_path, damage):
    value = snapshot(tmp_path)
    payload = value.payload
    if damage == "changed":
        payload.path.write_bytes(b"{}")
    elif damage == "public":
        payload.path.chmod(0o644)
    elif damage == "symlink":
        other = tmp_path / "other"
        payload.path.rename(other)
        payload.path.symlink_to(other)
    elif damage == "wrong_hash":
        payload = replace(payload, fingerprint="0" * 64)
    else:
        payload.path.write_bytes(b"{")
    with pytest.raises(ValueError):
        payload.verify()


def test_prefix_read_still_checks_whole_file_and_cancellation_closes(tmp_path):
    payload = saved(tmp_path, b"abcdef")
    with payload.open() as reader:
        assert reader.read(1) == b"a"
    with pytest.raises(ValueError, match="cancelled"):
        with payload.open(cancelled=lambda: True) as reader:
            reader.read(1)
    payload.verify()


def test_writer_records_equal_claims_and_checks_replay_payload_again(db, tmp_path):
    value = snapshot(tmp_path)
    with db.cursor() as cur:
        authorize_connection(cur, value)
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
    assert not persist_public(db, value)["replayed"]
    assert persist_public(db, value)["replayed"]
    value.payload.path.write_bytes(b"{}")
    with pytest.raises(ValueError, match="receipt"):
        persist_public(db, value)


def test_file_change_after_first_batch_rolls_back_the_entire_attempt(
    db, tmp_path, monkeypatch
):
    import standalone.evidence_pipeline.persistence.public_store as store

    raw = json.dumps(
        {
            f"synthetic-package-{i}": {
                "CVE-2099-1234": {"description": "synthetic", "releases": {}}
            }
            for i in range(260)
        }
    ).encode()
    value = snapshot(tmp_path, raw)
    with db.cursor() as cur:
        authorize_connection(cur, value)
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
    original = store._insert_many
    changed = False

    def change_file(cursor, schema, table, values, conflict=False):
        nonlocal changed
        original(cursor, schema, table, values, conflict)
        if table == "public_claims" and not changed:
            changed = True
            value.payload.path.write_bytes(raw[:-1] + b",")

    monkeypatch.setattr(store, "_insert_many", change_file)
    with pytest.raises(ValueError):
        persist_public(db, value)
    assert changed
    with db.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM evidence.collection_attempts WHERE id=%s",
            (value.execution_id,),
        )
        assert cur.fetchone() == (0,)
        cur.execute(
            "SELECT count(*) FROM evidence.source_revisions WHERE connection_id=%s",
            (value.scope.connection_id,),
        )
        assert cur.fetchone() == (0,)


def test_collection_streams_synthetic_file_and_replays_saved_bytes(
    tmp_path, monkeypatch
):
    from standalone.evidence_pipeline.collection.public_collection import prepare
    from .test_cvrf_updates import document as active_document, source
    from standalone.evidence_pipeline.collection.public_transport import endpoint

    # Exercise the shared streaming transport through an active source. The
    # retained Debian normalisation/rollback contracts above remain covered.
    chosen = replace(source(), scope_reference=endpoint("MSRC", month="2026-Sep"))
    fixture = saved(tmp_path, json.dumps(active_document()).encode())
    bundle = tmp_path / "bundle"
    run = str(uuid4())
    value = prepare(chosen, run, bundle, month="2026-Sep", synthetic_payload=fixture)
    assert isinstance(value.payload, FilePayload) and value.complete
    fixture.path.unlink()

    def network(*args, **kwargs):
        raise AssertionError("Unexpected network")

    monkeypatch.setattr("http.client.HTTPSConnection", network)
    assert prepare(chosen, run, bundle, month="2026-Sep", replay_only=True) == value
