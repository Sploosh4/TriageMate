"""Source clocks retain their meaning and cannot be replaced with import time."""

from contextlib import closing
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock
from uuid import uuid4

import pytest

from standalone.evidence_pipeline.parsing import public_inputs
from standalone.evidence_pipeline.commands import register, ingest_public
from standalone.evidence_pipeline.collection.public_collection import prepare
from standalone.evidence_pipeline.collection.public_transport import endpoint
from standalone.evidence_pipeline.runtime import connect
from standalone.evidence_pipeline.test_public_commands import clear_public
from standalone.evidence_pipeline.test_public_inputs import scope, epss, kev, nvd, wire

from . import provider_age
from .process_worker import PublicRecipe


NOW = datetime(2026, 9, 15, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    "offset,expected",
    [
        (None, "unknown"),
        (-172800, "stale"),
        (-172799, "healthy"),
        (300, "healthy"),
        (301, "future"),
    ],
)
def test_age_and_clock_skew_boundaries(offset, expected):
    clock = None if offset is None else NOW + timedelta(seconds=offset)
    assert provider_age.classify(clock, NOW, max_age_seconds=172800) == expected


def test_source_clock_semantics():
    first = public_inputs.parse_epss_csv(epss(), scope=scope("FIRST"))
    stamp, basis, precision = provider_age.provider_clock(first)
    assert (stamp, basis, precision) == (
        datetime(2026, 9, 12, tzinfo=timezone.utc),
        "score_date",
        "date",
    )
    kev_feed = public_inputs.parse_kev_json(wire(kev()), scope=scope("CISA"))
    assert provider_age.provider_clock(kev_feed)[1:] == (
        "catalogue_release",
        "timestamp",
    )
    nvd_feed = public_inputs.parse_nvd_json(wire(nvd()), scope=scope("NVD"))
    assert provider_age.provider_clock(nvd_feed) == (
        nvd_feed.timestamp,
        "response_timestamp",
        "timestamp",
    )
    with pytest.raises(ValueError):
        provider_age.provider_clock(object())


@pytest.mark.parametrize(
    "age,skew", [(True, 300), (0, 300), (172800, -1), (172800, True)]
)
def test_invalid_thresholds_rejected(age, skew):
    with pytest.raises(ValueError):
        provider_age.classify(None, NOW, max_age_seconds=age, clock_skew_seconds=skew)


def test_committed_feed_clock_and_cache_do_not_use_collection_time(
    tmp_path, monkeypatch
):
    chosen = replace(
        scope("FIRST"), connection_id=str(uuid4()), scope_reference=endpoint("FIRST")
    )
    cve = ("CVE-2099-" + str(uuid4().int))[:28]
    run = str(uuid4())
    payload = epss().replace(b"CVE-2026-9999999", cve.encode())
    recipe = PublicRecipe(chosen, tmp_path)
    cache = {}
    try:
        register(chosen)
        saved = prepare(chosen, run, tmp_path / run, synthetic_payload=payload)
        ingest_public(saved)
        with closing(connect()) as conn, conn, conn.cursor() as cursor:
            observation = provider_age.read_clock(cursor, recipe, cache=cache)
            assert observation["attempt_id"] == run
            assert observation["collected_at"] == saved.finished_at.isoformat()
            assert observation["provider_time"] == "2026-09-12T00:00:00+00:00"
            assert (
                provider_age.classify(
                    datetime.fromisoformat(observation["provider_time"]),
                    NOW,
                    max_age_seconds=172800,
                )
                == "stale"
            )
            monkeypatch.setattr(
                provider_age,
                "prepare",
                lambda *a, **k: pytest.fail("Reparsed unchanged feed"),
            )
            assert provider_age.read_clock(cursor, recipe, cache=cache) == observation
    finally:
        clear_public(chosen, cve)


def test_mismatched_wire_is_unknown_without_older_fallback(tmp_path, monkeypatch):
    chosen = replace(scope("FIRST"), connection_id=str(uuid4()))
    cursor = Mock()
    cursor.fetchone.return_value = (str(uuid4()), NOW, "expected")
    monkeypatch.setattr(
        provider_age,
        "prepare",
        lambda *a, **k: Mock(complete=True, input_fingerprint="different"),
    )
    result = provider_age.read_clock(cursor, PublicRecipe(chosen, tmp_path))
    assert result["provider_time"] is None
    assert cursor.execute.call_count == 1


@pytest.mark.parametrize(
    "source,kind", [("FIRST", "epss"), ("CVE", "records"), ("CISA", "vulnrichment")]
)
def test_cached_clock_cannot_cross_configured_bundle_roots(
    tmp_path, monkeypatch, source, kind
):
    chosen = replace(
        scope("FIRST"), connection_id=str(uuid4()), source=source, input_kind=kind
    )
    cursor = Mock()
    run = str(uuid4())
    cursor.fetchone.return_value = (run, NOW, "expected")
    original = PublicRecipe(chosen, tmp_path / "original")
    moved = replace(original, bundle_root=tmp_path / "missing")
    prepared = Mock(complete=True, input_fingerprint="expected", finished_at=NOW)
    reads = Mock(side_effect=[prepared, OSError("Missing configured bundle")])
    monkeypatch.setattr(provider_age, "prepare", reads)
    monkeypatch.setattr(
        provider_age, "provider_clock", lambda feed: (NOW, "score_date", "date")
    )
    cache = {}
    verified = provider_age.read_clock(cursor, original, cache=cache)
    assert verified["provider_time"] == NOW.isoformat()
    assert provider_age.read_clock(cursor, original, cache=cache) == verified
    missing = provider_age.read_clock(cursor, moved, cache=cache)
    assert missing["attempt_id"] == run
    assert missing["provider_time"] is None
    if source != "FIRST":
        assert verified["health_time"] == NOW.isoformat()
        assert missing["health_time"] is None
    assert reads.call_count == 2
    assert reads.call_args.args[2] == moved.bundle_root / run


def test_monitor_journals_one_episode_and_resolves_new_feed(tmp_path):
    from standalone.evidence_pipeline.runtime import local_database
    from .dispatch import Dispatcher
    from .notifications import load
    from .provider_monitor import ProviderMonitor, ProviderPolicy
    from .supervisor import PostgresRepository

    chosen = replace(
        scope("FIRST"), connection_id=str(uuid4()), scope_reference=endpoint("FIRST")
    )
    cve = ("CVE-2099-" + str(uuid4().int))[:28]
    payload = epss().replace(b"CVE-2026-9999999", cve.encode())
    key = "synthetic-provider-age-" + str(uuid4())
    ticks = [0]
    monitor = ProviderMonitor(
        key,
        [ProviderPolicy(PublicRecipe(chosen, tmp_path), 172800)],
        clock=lambda: ticks[0],
    )
    try:
        register(chosen)
        PostgresRepository(key).commit(0, Dispatcher([], now=NOW))
        run = str(uuid4())
        ingest_public(prepare(chosen, run, tmp_path / run, synthetic_payload=payload))
        monitor.check(NOW)
        first = load(key)
        assert len(first) == 1 and first[0]["synthetic"]
        assert first[0]["status"] == "unresolved"
        ticks[0] += 61
        monitor.check(NOW + timedelta(seconds=61))
        with local_database().connect() as conn, conn.cursor() as cursor:
            cursor.execute(
                "SELECT count(*) FROM evidence_pipeline.operation_events WHERE service_key=%s",
                (key,),
            )
            assert cursor.fetchone() == (1,)
        run = str(uuid4())
        ingest_public(
            prepare(
                chosen,
                run,
                tmp_path / run,
                synthetic_payload=payload.replace(b"2026-09-12", b"2026-09-15"),
            )
        )
        ticks[0] += 61
        monitor.check(NOW + timedelta(seconds=122))
        resolved = load(key)
        assert len(resolved) == 1 and resolved[0]["id"] == first[0]["id"]
        assert resolved[0]["status"] == "resolved"
    finally:
        with local_database().connect() as conn, conn.cursor() as cursor:
            cursor.execute(
                "DELETE FROM evidence_pipeline.operation_events WHERE service_key=%s",
                (key,),
            )
            cursor.execute(
                "DELETE FROM evidence_pipeline.operation_checkpoints WHERE service_key=%s",
                (key,),
            )
        clear_public(chosen, cve)


def test_record_modified_clock_keeps_semantics_and_unknowns():
    from standalone.evidence_pipeline.test_advisory_feeds import fixture
    from standalone.evidence_pipeline.parsing.advisory_feeds import parse_advisory

    chosen, payload = fixture("Palo Alto Networks")
    assert provider_age.provider_clock(parse_advisory(payload, scope=chosen)) == (
        None,
        None,
        None,
    )
    assert provider_age.record_clock(
        ["2026-09-15T00:00:00Z", "2026-09-14T00:00:00Z"]
    ) == (
        datetime(2026, 9, 14, tzinfo=timezone.utc),
        "record_last_modified",
        "timestamp",
    )
    assert provider_age.record_clock(["2026-09-15T00:00:00Z", None]) == (
        None,
        None,
        None,
    )
    assert provider_age.record_clock(["2026-09-15T00:00:00"]) == (None, None, None)
    assert provider_age.record_clock(["2026-09-15T00:00:00"], cve_times=True)[
        0
    ] == datetime(2026, 9, 15, tzinfo=timezone.utc)
    assert provider_age.clock_basis("CISA", "vulnrichment") == "record_last_modified"
    assert provider_age.clock_basis("CISA", "kev") == "catalogue_release"


def test_verified_unknown_clock_is_cached_without_reparsing(tmp_path, monkeypatch):
    from standalone.evidence_pipeline.test_advisory_feeds import fixture
    from standalone.evidence_pipeline.parsing.public_snapshot import PublicSnapshot
    from uuid import uuid4

    chosen, payload = fixture("Palo Alto Networks")
    now = datetime(2026, 9, 16, tzinfo=timezone.utc)
    snapshot = PublicSnapshot(chosen, str(uuid4()), now, now, "success", True, payload)
    calls = []

    def replay(*args, **kwargs):
        calls.append(True)
        return snapshot

    monkeypatch.setattr(provider_age, "prepare", replay)

    class Cursor:
        def execute(self, *args):
            pass

        def fetchone(self):
            return snapshot.execution_id, now, snapshot.input_fingerprint

    recipe = PublicRecipe(chosen, tmp_path)
    cache = {}
    first = provider_age.read_clock(Cursor(), recipe, cache=cache)
    assert (
        first["provider_time"] is None and first["attempt_id"] == snapshot.execution_id
    )
    assert provider_age.read_clock(Cursor(), recipe, cache=cache) == first
    assert calls == [True]


@pytest.mark.parametrize("streamed", [False, True])
@pytest.mark.parametrize(
    "value,known",
    [
        ("2026-09-15T07:00:00Z", True),
        ("2026-09-15T15:00:00+08:00", True),
        ("2026-09-15T07:00:00", False),
        ("2026-09-15", False),
        (None, False),
        ("invalid", False),
    ],
)
def test_msrc_document_clock_requires_explicit_timezone(
    tmp_path, streamed, value, known
):
    import json
    from standalone.evidence_pipeline.test_cvrf_updates import document, source
    from standalone.evidence_pipeline.parsing.cvrf_updates import parse_cvrf_updates
    from standalone.evidence_pipeline.parsing.cvrf_stream import StreamedCvrfUpdates
    from standalone.evidence_pipeline.test_cvrf_stream import saved

    raw = document()
    raw["DocumentTracking"] = {"CurrentReleaseDate": value}
    payload = json.dumps(raw).encode()
    chosen = source()
    feed = (
        StreamedCvrfUpdates(chosen, saved(tmp_path, payload))
        if streamed
        else parse_cvrf_updates(payload, scope=chosen)
    )
    expected = (
        (datetime(2026, 9, 15, 7, tzinfo=timezone.utc), "document_release", "timestamp")
        if known
        else (None, None, None)
    )
    assert provider_age.provider_clock(feed) == expected
    assert provider_age.clock_basis("MSRC", "security_updates") == "document_release"


@pytest.mark.parametrize(
    "damage",
    [None, "missing", "duplicate", "invalid_identity", "naive", "missing_clock"],
)
def test_attack_collection_clock_never_uses_technique_date(damage):
    from uuid import uuid4
    from standalone.evidence_pipeline.test_attack_definitions import (
        definition,
        payload,
        scope,
    )
    from standalone.evidence_pipeline.parsing.attack_definitions import parse_attack

    collection = {
        "type": "x-mitre-collection",
        "id": "x-mitre-collection--" + str(uuid4()),
        "modified": "2026-09-15T07:00:00Z",
    }
    if damage == "invalid_identity":
        collection["id"] = "unverified"
    if damage == "naive":
        collection["modified"] = "2026-09-15T07:00:00"
    if damage == "missing_clock":
        del collection["modified"]
    collections = (
        []
        if damage == "missing"
        else [collection] * (2 if damage == "duplicate" else 1)
    )
    feed = parse_attack(payload([definition(), *collections]), scope=scope())
    expected = (
        (
            datetime(2026, 9, 15, 7, tzinfo=timezone.utc),
            "collection_modified",
            "timestamp",
        )
        if damage is None
        else (None, None, None)
    )
    assert provider_age.provider_clock(feed) == expected
    assert (
        provider_age.clock_basis("MITRE ATT&CK", "enterprise_definitions")
        == "collection_modified"
    )


@pytest.mark.parametrize("damage", [None, "missing", "invalid", "empty"])
def test_catalog_clock_uses_publisher_date_with_date_precision(damage):
    from standalone.evidence_pipeline.parsing.advisory_feeds import parse_advisory
    from standalone.evidence_pipeline.collection.catalog_collection import catalog_scope
    from standalone.evidence_pipeline.parsing.update_catalog import endpoint
    from standalone.evidence_pipeline.test_update_catalog import payload, ID

    feed = parse_advisory(payload(), scope=catalog_scope("synthetic", endpoint(ID)))
    if damage == "empty":
        feed = replace(feed, records=())
    elif damage:
        fields = dict(feed.records[0].fields)
        fields["notice"] = dict(
            fields["notice"], updated_at=None if damage == "missing" else "13/45/2026"
        )
        feed = replace(feed, records=(replace(feed.records[0], fields=fields),))
    expected = (
        (datetime(2026, 9, 16, tzinfo=timezone.utc), "record_last_modified", "date")
        if damage is None
        else (None, None, None)
    )
    assert provider_age.provider_clock(feed) == expected


def test_record_clock_large_iterator_retains_bounded_memory():
    import tracemalloc

    tracemalloc.start()
    try:
        result = provider_age.record_clock(
            "2026-09-15T00:00:00Z" for _ in range(100_000)
        )
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert result == (NOW, "record_last_modified", "timestamp")
    # A list of 100,000 parsed datetimes exceeds this by several megabytes.
    assert peak < 500_000


@pytest.mark.parametrize("ending", [None, "invalid", "2026-09-14T00:00:00Z"])
def test_record_clock_validates_final_iterator_value(ending):
    from itertools import chain, repeat

    result = provider_age.record_clock(
        chain(repeat("2026-09-15T00:00:00Z", 1000), [ending])
    )
    expected = (
        (
            datetime(2026, 9, 14, tzinfo=timezone.utc),
            "record_last_modified",
            "timestamp",
        )
        if ending == "2026-09-14T00:00:00Z"
        else (None, None, None)
    )
    assert result == expected


@pytest.mark.parametrize(
    "header",
    [
        b"# Synthetic notice - 20990101001",
        b"# Synthetic notice - 209901010002",
        b"## Synthetic notice",
    ],
)
def test_wasoc_filename_and_heading_do_not_invent_publisher_clock(header):
    from standalone.evidence_pipeline.test_wasoc_advisories import scope, BODY
    from standalone.evidence_pipeline.parsing.advisory_feeds import parse_advisory

    feed = parse_advisory(header + b"\n" + BODY.split(b"\n", 1)[1], scope=scope())
    assert provider_age.provider_clock(feed) == (None, None, None)


@pytest.mark.parametrize(
    "damage", [None, "missing", "fingerprint", "timestamp", "incomplete"]
)
@pytest.mark.parametrize("published", [None, datetime(2010, 1, 1, tzinfo=timezone.utc)])
@pytest.mark.parametrize("source,kind", sorted(provider_age.COLLECTION_HEALTH_INPUTS))
def test_individual_record_collection_health_preserves_publication(
    tmp_path, monkeypatch, damage, published, source, kind
):
    from types import SimpleNamespace
    from standalone.evidence_pipeline.contracts import SourceScope

    chosen = SourceScope(
        str(uuid4()),
        source,
        kind,
        "https://example.test/synthetic-record",
        "synthetic",
        "TriageMate generated synthetic MSRC health fixture",
    )
    cursor = Mock()
    cursor.fetchone.return_value = (str(uuid4()), NOW, "expected")

    def prepare_fixture(*args, **kwargs):
        assert kwargs["replay_only"] is True
        if damage == "missing":
            raise OSError("synthetic missing bundle")
        return SimpleNamespace(
            complete=damage != "incomplete",
            input_fingerprint="different" if damage == "fingerprint" else "expected",
            finished_at=NOW - timedelta(days=1) if damage == "timestamp" else NOW,
            feed=lambda: object(),
        )

    monkeypatch.setattr(provider_age, "prepare", prepare_fixture)
    monkeypatch.setattr(
        provider_age,
        "provider_clock",
        lambda feed: (
            (published, "document_release", "timestamp")
            if published
            else (None, None, None)
        ),
    )
    cache = {}
    result = provider_age.read_clock(
        cursor, PublicRecipe(chosen, tmp_path), cache=cache
    )
    assert result["health_basis"] == "successful_collection"
    assert result["health_time"] == (NOW.isoformat() if damage is None else None)
    assert result["provider_time"] == (
        published.isoformat() if damage is None and published else None
    )
    assert bool(cache) is (damage is None)


@pytest.mark.parametrize(
    "damage", ["receipt", "payload", "wire", "directory", "corrupt", "replace"]
)
def test_cached_provider_clock_rechecks_changed_proof_and_recovers(tmp_path, damage):
    import shutil

    chosen = replace(scope("FIRST"), scope_reference=endpoint("FIRST"))
    run = str(uuid4())
    bundle = tmp_path / run
    saved = prepare(chosen, run, bundle, synthetic_payload=epss())
    original = {p.name: p.read_bytes() for p in bundle.iterdir() if p.is_file()}
    cursor = Mock()
    cursor.fetchone.return_value = (run, saved.finished_at, saved.input_fingerprint)
    recipe = PublicRecipe(chosen, tmp_path)
    cache = {}
    before = provider_age.read_clock(cursor, recipe, cache=cache)
    assert before["provider_time"] is not None
    if damage == "directory":
        shutil.rmtree(bundle)
    elif damage == "corrupt":
        (bundle / "payload.bin").write_bytes(b"synthetic-corruption")
    elif damage == "replace":
        replacement = bundle / "replacement"
        replacement.write_bytes(b"synthetic-corruption")
        replacement.replace(bundle / "payload.bin")
    else:
        (
            bundle
            / {"receipt": "receipt.json", "payload": "payload.bin", "wire": "wire.bin"}[
                damage
            ]
        ).unlink()
    after = provider_age.read_clock(cursor, recipe, cache=cache)
    assert after["provider_time"] is None
    assert after["attempt_id"] == run
    assert not cache
    bundle.mkdir(mode=0o700, exist_ok=True)
    for name, content in original.items():
        (bundle / name).write_bytes(content)
        (bundle / name).chmod(0o600)
    assert provider_age.read_clock(cursor, recipe, cache=cache) == before


def test_proof_change_during_clock_read_is_not_cached(tmp_path, monkeypatch):
    chosen = replace(scope("FIRST"), scope_reference=endpoint("FIRST"))
    run = str(uuid4())
    bundle = tmp_path / run
    saved = prepare(chosen, run, bundle, synthetic_payload=epss())
    cursor = Mock()
    cursor.fetchone.return_value = (run, saved.finished_at, saved.input_fingerprint)
    original_clock = provider_age.provider_clock

    def changed(feed):
        result = original_clock(feed)
        (bundle / "receipt.json").unlink()
        return result

    monkeypatch.setattr(provider_age, "provider_clock", changed)
    cache = {}
    result = provider_age.read_clock(
        cursor, PublicRecipe(chosen, tmp_path), cache=cache
    )
    assert result["provider_time"] is None
    assert not cache
