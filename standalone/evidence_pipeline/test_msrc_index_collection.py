"""Generated index bundles and mocked HTTP; no publisher access."""

import hashlib
import json
from uuid import uuid4
import pytest
from standalone.evidence_pipeline.collection import msrc_index_collection as collection
from .file_payload import FilePayload
from standalone.evidence_pipeline.contracts import PublicDownload
from .test_msrc_publications import entry, CONTEXT


def payload():
    return json.dumps({"@odata.context": CONTEXT, "value": [entry()]}).encode()


def test_synthetic_replay_preserves_dates_and_never_fetches(tmp_path, monkeypatch):
    monkeypatch.setattr(
        collection, "_download_url", lambda *a, **k: pytest.fail("network")
    )
    root, execution = tmp_path / "index", str(uuid4())
    first = collection.prepare(
        root, execution, origin="synthetic", synthetic_payload=payload()
    )
    second = collection.prepare(root, execution, origin="synthetic", replay_only=True)
    assert first == second and first.complete
    assert [item.publication_id for item in first.items()] == ["2099-Jan"]
    with pytest.raises(ValueError):
        collection.prepare(root, str(uuid4()), origin="synthetic", replay_only=True)
    with pytest.raises(ValueError):
        collection.prepare(root, execution, origin="public", replay_only=True)
    (root / "wire.bin").write_bytes(b"changed")
    with pytest.raises(ValueError):
        collection.prepare(root, execution, origin="synthetic", replay_only=True)


def test_mocked_public_transport_streams_and_replays(tmp_path, monkeypatch):
    calls = []

    def download(url, *, save_to, cancelled):
        calls.append(url)
        assert not cancelled()
        collection._write(save_to, payload())
        data = FilePayload(save_to.resolve(), hashlib.sha256(payload()).hexdigest())
        now = collection.datetime.now(collection.timezone.utc)
        return PublicDownload(url, now, now, data, data)

    monkeypatch.setattr(collection, "_download_url", download)
    root, execution = tmp_path / "index", str(uuid4())
    result = collection.prepare(root, execution, origin="public", allow_network=True)
    assert result.complete and isinstance(result.payload, FilePayload)
    assert (
        collection.prepare(root, execution, origin="public", replay_only=True) == result
    )
    assert len(calls) == 1


@pytest.mark.parametrize("interruption", [False, True])
def test_partial_transport_cleanup_and_no_automatic_refetch(
    tmp_path, monkeypatch, interruption
):
    calls = []

    def broken(url, *, save_to, cancelled):
        calls.append(url)
        collection._write(save_to, b"partial")
        if interruption:
            raise KeyboardInterrupt("synthetic interruption")
        raise ValueError("synthetic transport failure")

    monkeypatch.setattr(collection, "_download_url", broken)
    root, execution = tmp_path / "index", str(uuid4())
    if interruption:
        with pytest.raises(KeyboardInterrupt):
            collection.prepare(root, execution, origin="public", allow_network=True)
        with pytest.raises(ValueError, match="Interrupted"):
            collection.prepare(root, execution, origin="public", allow_network=True)
    else:
        first = collection.prepare(root, execution, origin="public", allow_network=True)
        assert first.error_code == "public_transport_failed"
        assert (
            collection.prepare(root, execution, origin="public", replay_only=True)
            == first
        )
    assert not (root / "wire.bin").exists() and len(calls) == 1


def test_invalid_complete_bytes_are_retained_as_failure(tmp_path):
    root, execution = tmp_path / "index", str(uuid4())
    result = collection.prepare(
        root, execution, origin="synthetic", synthetic_payload=b"{}"
    )
    assert (
        result.error_code == "invalid_msrc_index"
        and (root / "wire.bin").read_bytes() == b"{}"
    )
    assert (
        collection.prepare(root, execution, origin="synthetic", replay_only=True)
        == result
    )
    with pytest.raises(ValueError):
        list(result.items())


def test_no_authority_and_pre_cancelled_attempt_never_fetch(tmp_path, monkeypatch):
    monkeypatch.setattr(
        collection, "_download_url", lambda *a, **k: pytest.fail("network")
    )
    for options in (
        {"origin": "public"},
        {"origin": "public", "synthetic_payload": payload()},
        {"origin": "synthetic", "allow_network": True},
    ):
        with pytest.raises(ValueError):
            collection.prepare(tmp_path / str(uuid4()), str(uuid4()), **options)
    result = collection.prepare(
        tmp_path / "cancelled",
        str(uuid4()),
        origin="public",
        allow_network=True,
        cancelled=lambda: True,
    )
    assert result.error_code == "public_cancelled" and result.payload is None


def test_saved_payload_symlink_is_rejected(tmp_path):
    root, execution = tmp_path / "index", str(uuid4())
    collection.prepare(root, execution, origin="synthetic", synthetic_payload=payload())
    wire = root / "wire.bin"
    wire.rename(root / "original.bin")
    wire.symlink_to(root / "original.bin")
    with pytest.raises(ValueError, match="symlink"):
        collection.prepare(root, execution, origin="synthetic", replay_only=True)


def test_elapsed_deadline_prevents_transport_start(tmp_path, monkeypatch):
    ticks = iter([0.0, 61.0, 61.0])
    monkeypatch.setattr(collection.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(
        collection, "_download_url", lambda *a, **k: pytest.fail("expired request")
    )
    result = collection.prepare(
        tmp_path / "expired", str(uuid4()), origin="public", allow_network=True
    )
    assert result.error_code == "public_cancelled" and result.payload is None
