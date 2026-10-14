"""Saved index and exact committed receipts are both necessary for success."""

import hashlib
import json
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

import pytest

from standalone.evidence_pipeline.test_redhat_collection_run import INDEX

from . import redhat_proof as proof


def saved(tmp_path):
    run = str(uuid4())
    # Retained proof contracts remain testable without reopening the collector.
    bundle = tmp_path / run
    bundle.mkdir(mode=0o700)
    request = dict(origin="synthetic", execution_id=run, source_url=proof.INDEX_URL)
    for name, payload in {
        "index.txt": INDEX,
        "request.json": json.dumps(request).encode(),
        "receipt.json": json.dumps(
            dict(request, fingerprint=hashlib.sha256(INDEX).hexdigest())
        ).encode(),
    }.items():
        path = bundle / name
        path.write_bytes(payload)
        path.chmod(0o600)
    return run


@pytest.mark.parametrize(
    "damage", [None, "index", "receipt", "request", "permissions", "symlink"]
)
def test_saved_index_has_exact_binding(tmp_path, damage):
    run = saved(tmp_path)
    bundle = tmp_path / run
    if damage == "index":
        (bundle / "index.txt").write_bytes(INDEX.replace(b"1234", b"9999"))
    elif damage in {"receipt", "request"}:
        (bundle / (damage + ".json")).write_text("{}")
    elif damage == "permissions":
        (bundle / "index.txt").chmod(0o644)
    elif damage == "symlink":
        (bundle / "index.txt").rename(bundle / "retained-index")
        (bundle / "index.txt").symlink_to(bundle / "retained-index")
    if damage:
        with pytest.raises((ValueError, OSError)):
            proof.saved_index(tmp_path, "synthetic", run)
    else:
        actual, digest, entries = proof.saved_index(tmp_path, "synthetic", run)
        assert actual == bundle and digest == hashlib.sha256(INDEX).hexdigest()
        assert [entry.path for entry in entries] == INDEX.decode().splitlines()
        with pytest.raises(ValueError):
            proof.saved_index(tmp_path, "public", run)


@pytest.mark.parametrize(
    "damage", [None, "missing", "contract", "index", "input", "run", "imports"]
)
def test_journal_declaration_binds_membership_and_configuration(
    tmp_path, monkeypatch, damage
):
    run = saved(tmp_path)
    _, digest, _ = proof.saved_index(tmp_path, "synthetic", run)
    job = SimpleNamespace(input_id=str(uuid4()), run_id=run)
    declaration = proof.event(job, "synthetic", "a" * 64, digest)
    if damage == "missing":
        declaration = None
    elif damage in {"contract", "index", "input", "run"}:
        field = {
            "contract": "worker_contract",
            "index": "index_sha256",
            "input": "input_id",
            "run": "run_id",
        }[damage]
        declaration[field] = "changed"
    monkeypatch.setattr(proof, "saved_event", lambda *args: declaration)
    monkeypatch.setattr(proof, "imports_committed", lambda *args: damage != "imports")
    assert proof.committed(
        Mock(), "synthetic-proof", job, "synthetic", tmp_path, "a" * 64
    ) is (damage is None)


def test_ambiguous_declaration_is_rejected():
    cursor = Mock()
    cursor.fetchall.return_value = [({},), ({},)]
    with pytest.raises(ValueError, match="Ambiguous"):
        proof.saved_event(cursor, "synthetic-proof", str(uuid4()))
