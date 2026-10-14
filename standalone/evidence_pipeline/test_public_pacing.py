"""NVD pacing without real sleeps or public requests; real shared-lock coverage."""

from concurrent.futures import ThreadPoolExecutor

import pytest

from standalone.evidence_pipeline.collection import public_pacing as pacing


def test_nested_request_path_waits_once_and_skips_synthetic(monkeypatch):
    events = []

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def close(self):
            events.append("closed")

        def cursor(self):
            return self

        def set_session(self, **kwargs):
            assert kwargs == {"readonly": True}

        def execute(self, statement, params=None):
            events.append((statement, params))

    monkeypatch.setattr(pacing, "connect", Connection)
    monkeypatch.setattr(pacing.time, "sleep", lambda duration: events.append(duration))
    with pacing.paced("NVD"):
        with pacing.paced("NVD"):
            events.append("request")
    assert events == [
        ("SET LOCAL lock_timeout='100ms'", None),
        ("SELECT pg_advisory_xact_lock(%s)", (pacing.NVD_LOCK,)),
        6.1,
        ("SELECT 1", None),
        ("SELECT 1", None),
        "request",
        "closed",
    ]
    events.clear()
    with pacing.paced("NVD", origin="synthetic"), pacing.paced("CVE"):
        pass
    assert events == []


def test_shared_database_slot_defers_other_worker_and_releases_after_failure(
    monkeypatch,
):
    waits = []
    monkeypatch.setattr(pacing.time, "sleep", lambda duration: waits.append(duration))

    def enter():
        with pacing.paced("NVD"):
            return "acquired"

    with ThreadPoolExecutor(max_workers=1) as pool:
        with pytest.raises(RuntimeError, match="synthetic interruption"):
            with pacing.paced("NVD"):
                with pytest.raises(pacing.PublicSourceBusy):
                    pool.submit(enter).result(timeout=5)
                raise RuntimeError("synthetic interruption")
        assert pool.submit(enter).result(timeout=5) == "acquired"
    assert waits == [6.1, 6.1]


def test_github_slot_is_distinct_nested_and_synthetic_skips(monkeypatch):
    waits = []
    monkeypatch.setattr(pacing.time, "sleep", lambda seconds: waits.append(seconds))
    with pacing.paced("NVD"):
        with pacing.paced("GitHub REST"):
            with pacing.paced("GitHub REST"):
                pass
    assert waits == [6.1, 30.0, 30.0, 1.0]
    waits.clear()
    with pacing.paced("GitHub REST", origin="synthetic"):
        pass
    assert not waits


def test_github_shared_slot_defers_concurrent_worker(monkeypatch):
    monkeypatch.setattr(pacing.time, "sleep", lambda seconds: None)

    def enter():
        with pacing.paced("GitHub REST"):
            return "acquired"

    with ThreadPoolExecutor(max_workers=1) as pool:
        with pacing.paced("GitHub REST"):
            with pytest.raises(pacing.PublicSourceBusy):
                pool.submit(enter).result(timeout=5)
        assert pool.submit(enter).result(timeout=5) == "acquired"
