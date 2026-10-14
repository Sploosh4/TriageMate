"""Synthetic public HTTP substitutes; no test contacts publisher endpoints."""

from dataclasses import replace
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from standalone.evidence_pipeline.collection import public_collection as collector
from standalone.evidence_pipeline.collection.public_transport import (
    PublicDownload,
    endpoint,
)
from .test_public_inputs import epss, scope


def public_scope():
    return replace(scope("FIRST"), origin="public", scope_reference=endpoint("FIRST"))


def test_synthetic_bundle_and_offline_replay_never_fetch(tmp_path, monkeypatch):
    def no_fetch(*args, **kwargs):
        pytest.fail("Synthetic/replay path attempted network collection")

    monkeypatch.setattr(collector, "download", no_fetch)
    chosen = replace(public_scope(), origin="synthetic")
    execution = str(uuid4())
    bundle = tmp_path / "synthetic"
    first = collector.prepare(chosen, execution, bundle, synthetic_payload=epss())
    assert first.complete and first.scope.origin == "synthetic"
    assert collector.prepare(chosen, execution, bundle, replay_only=True) == first
    with pytest.raises(ValueError, match="differs"):
        collector.prepare(chosen, execution, bundle, synthetic_payload=epss() + b"\n")
    with pytest.raises(ValueError, match="existing durable bundle"):
        collector.prepare(chosen, execution, tmp_path / "missing", replay_only=True)
    assert not (tmp_path / "missing").exists()
    with pytest.raises(ValueError, match="synthetic source"):
        collector.prepare(
            public_scope(), str(uuid4()), tmp_path / "wrong", synthetic_payload=epss()
        )
    assert not (tmp_path / "wrong").exists()


@pytest.mark.parametrize("source,kind", [("CVE", "records"), ("CISA", "vulnrichment")])
@pytest.mark.parametrize("mismatch", [False, True])
def test_cve_bundle_is_scoped_and_replayable(
    tmp_path, monkeypatch, source, kind, mismatch
):
    import json
    from .test_cve_program import document, scope as cve_scope

    cve = "CVE-2099-12345"
    url = endpoint(source, cve, input_kind=kind)
    selected = replace(
        cve_scope(),
        source=source,
        input_kind=kind,
        origin="public",
        scope_reference=url,
    )
    calls = []

    def fetch(provider, **kwargs):
        calls.append((provider, kwargs))
        raw = document()
        if mismatch:
            raw["cveMetadata"]["cveId"] = "CVE-2099-54321"
        wire = json.dumps(raw).encode()
        now = datetime.now(timezone.utc)
        return PublicDownload(url, now, now, wire, wire)

    monkeypatch.setattr(collector, "download", fetch)
    execution = str(uuid4())
    bundle = tmp_path / "cve"
    first = collector.prepare(selected, execution, bundle, cve=cve)
    assert first.complete is not mismatch
    assert collector.prepare(selected, execution, bundle, cve=cve) == first
    assert calls == [(source, {"cve": cve, "input_kind": kind})]


def test_update_bundle_replays_without_downloading_again(tmp_path, monkeypatch):
    import json
    from .test_cvrf_updates import document, source
    from standalone.evidence_pipeline.parsing.public_records import normalize_public

    url = endpoint("MSRC", month="2026-Sep")
    update_scope = replace(source(), origin="public", scope_reference=url)
    calls = []

    def fetch_updates(provider, **kwargs):
        calls.append((provider, kwargs))
        now = datetime.now(timezone.utc)
        wire = json.dumps(document()).encode()
        return PublicDownload(url, now, now, wire, wire)

    monkeypatch.setattr(collector, "download", fetch_updates)
    execution = str(uuid4())
    bundle = tmp_path / "updates"
    first = collector.prepare(update_scope, execution, bundle, month="2026-Sep")
    assert first.complete
    assert len(list(normalize_public(first.feed()))) == 1
    assert collector.prepare(update_scope, execution, bundle, month="2026-Sep") == first
    assert calls == [
        ("MSRC", {"cve": None, "month": "2026-Sep", "save_to": bundle / "wire.bin"})
    ]
    with pytest.raises(ValueError, match="fixed source endpoint"):
        collector.prepare(
            replace(update_scope, input_kind="advisories"),
            execution,
            tmp_path / "wrong",
            month="2026-Sep",
        )
    assert len(calls) == 1
    assert not (tmp_path / "wrong").exists()


@pytest.fixture
def fetch(monkeypatch):
    calls = []

    def fake(source, **kwargs):
        calls.append(source)
        now = datetime.now(timezone.utc)
        return PublicDownload(
            endpoint(source), now, now, b"synthetic compressed wire fixture", epss()
        )

    monkeypatch.setattr(collector, "download", fake)
    return calls


def test_retry_reuses_exact_download_and_timestamp(tmp_path, fetch):
    execution = str(uuid4())
    first = collector.prepare(public_scope(), execution, tmp_path / "bundle")
    second = collector.prepare(public_scope(), execution, tmp_path / "bundle")
    assert first == second
    assert fetch == ["FIRST"]
    assert first.complete
    assert (tmp_path / "bundle" / "receipt.json").stat().st_mode & 0o077 == 0


@pytest.mark.parametrize("file", ["payload.bin", "wire.bin"])
def test_retry_rejects_changed_bytes(tmp_path, fetch, file):
    execution = str(uuid4())
    collector.prepare(public_scope(), execution, tmp_path / "bundle")
    (tmp_path / "bundle" / file).write_bytes(b"changed")
    with pytest.raises(ValueError, match="differs"):
        collector.prepare(public_scope(), execution, tmp_path / "bundle")
    assert fetch == ["FIRST"]


def test_source_and_execution_reuse_rejected(tmp_path, fetch):
    execution = str(uuid4())
    collector.prepare(public_scope(), execution, tmp_path / "bundle")
    with pytest.raises(ValueError, match="different"):
        collector.prepare(public_scope(), str(uuid4()), tmp_path / "bundle")
    with pytest.raises(ValueError, match="different"):
        collector.prepare(
            replace(public_scope(), provenance="changed"),
            execution,
            tmp_path / "bundle",
        )


def test_partial_bundle_does_not_refetch(tmp_path, fetch):
    (tmp_path / "bundle").mkdir(mode=0o700)
    with pytest.raises(FileNotFoundError):
        collector.prepare(public_scope(), str(uuid4()), tmp_path / "bundle")
    assert fetch == []


def test_transport_failure_becomes_replayable_failure(tmp_path, monkeypatch):
    calls = []

    def fail(*args, **kwargs):
        calls.append(1)
        raise ValueError("Synthetic transport failure")

    monkeypatch.setattr(collector, "download", fail)
    execution = str(uuid4())
    first = collector.prepare(public_scope(), execution, tmp_path / "bundle")
    assert not first.complete and first.error_code == "public_transport_failed"
    assert collector.prepare(public_scope(), execution, tmp_path / "bundle") == first
    assert calls == [1]


def test_real_fetch_cannot_be_labelled_synthetic(tmp_path, fetch):
    with pytest.raises(ValueError, match="public scope"):
        collector.prepare(scope("FIRST"), str(uuid4()), tmp_path / "bundle")
    assert fetch == []


@pytest.mark.parametrize(
    "status,code",
    [
        (404, "public_not_found"),
        (410, "public_gone"),
        (403, "public_access_denied"),
        (429, "public_rate_limited"),
        (503, "public_unavailable"),
        (302, "public_http_failed"),
    ],
)
def test_failure_reason_survives_bundle_replay_without_retry(
    tmp_path, monkeypatch, status, code
):
    from standalone.evidence_pipeline.collection.public_transport import PublicHTTPError

    calls = []

    def fail(*args, **kwargs):
        calls.append(1)
        raise PublicHTTPError(status)

    monkeypatch.setattr(collector, "download", fail)
    execution = str(uuid4())
    chosen = public_scope()
    bundle = tmp_path / "failed"
    first = collector.prepare(chosen, execution, bundle)
    assert first.error_code == code
    assert not first.complete and first.outcome == "failure"
    with first.payload.open() as saved:
        assert saved.read(1) == b""
    assert not (bundle / "wire.bin").exists()
    assert collector.prepare(chosen, execution, bundle) == first
    assert calls == [1]


@pytest.mark.parametrize(
    "requested,complete", [("CVE-2099-9999999", True), ("CVE-2099-8888888", False)]
)
def test_advisory_collection_validates_requested_cve_and_replays(
    tmp_path, monkeypatch, requested, complete
):
    import json
    from .test_csaf import fixture, scope as csaf_scope

    chosen = replace(
        csaf_scope(), origin="public", scope_reference=endpoint("MSRC", requested)
    )
    calls = []

    def fake(source, *, cve):
        calls.append((source, cve))
        now = datetime.now(timezone.utc)
        raw = json.dumps(fixture()).encode()
        return PublicDownload(endpoint(source, cve), now, now, raw, raw)

    monkeypatch.setattr(collector, "download", fake)
    execution = str(uuid4())
    bundle = tmp_path / "msrc"
    first = collector.prepare(chosen, execution, bundle, cve=requested)
    assert first.complete == complete
    assert collector.prepare(chosen, execution, bundle, cve=requested) == first
    assert calls == [("MSRC", requested)]
    if not complete:
        assert first.error_code == "invalid_public_payload"


def test_new_nvd_download_uses_slot_but_replay_does_not(tmp_path, monkeypatch):
    from contextlib import contextmanager
    from .test_public_inputs import nvd, wire, CVE
    from standalone.evidence_pipeline.collection.public_pacing import PublicSourceBusy

    events = []

    @contextmanager
    def slot(source):
        assert source == "NVD"
        events.append("slot")
        yield
        events.append("released")

    def fetch(source, **kwargs):
        assert events[-1] == "slot"
        events.append("download")
        now = datetime.now(timezone.utc)
        payload = wire(nvd())
        return PublicDownload(endpoint(source, CVE), now, now, payload, payload)

    chosen = replace(
        scope("NVD"), origin="public", scope_reference=endpoint("NVD", CVE)
    )
    monkeypatch.setattr(collector, "paced", slot)
    monkeypatch.setattr(collector, "download", fetch)
    execution = str(uuid4())
    bundle = tmp_path / "nvd"
    first = collector.prepare(chosen, execution, bundle, cve=CVE)
    assert first.complete
    assert (
        collector.prepare(chosen, execution, bundle, cve=CVE, replay_only=True) == first
    )
    assert collector.prepare(chosen, execution, bundle, cve=CVE) == first
    assert events == ["slot", "download", "released"]

    def occupied(*args, **kwargs):
        raise PublicSourceBusy("Synthetic occupied slot")

    monkeypatch.setattr(collector, "paced", occupied)
    with pytest.raises(PublicSourceBusy):
        collector.prepare(chosen, str(uuid4()), tmp_path / "busy", cve=CVE)
    assert not (tmp_path / "busy").exists()
    assert events == ["slot", "download", "released"]
