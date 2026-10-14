"""Small transactional PostgreSQL checks; synthetic rows always roll back."""

from dataclasses import replace
import json
from uuid import uuid4

import psycopg2
import pytest

from standalone.evidence_pipeline.persistence.authority import authorize_connection
from standalone.evidence_pipeline.persistence.store import atomic, persist_devices
from standalone.evidence_pipeline.test_store import db as db, snapshot as snapshot
from backend.database.schema import verify

from .os_update_evidence import canonical
from .os_update_store import persist
from .store import persist as persist_inventory
from .test_os_update_evidence import sample, change
from .test_store import configured as configured, inventory


@pytest.fixture
def evidence(db, configured):
    device, selected, binding = configured
    with db.cursor() as cur:
        verify(cur)
        cur.execute("SET LOCAL statement_timeout=10000")
    bundle, _ = sample(binding)
    devices = json.loads(bundle["sources"]["devices-0"]["text"])["value"]
    defender = replace(
        device,
        scope=replace(device.scope, connection_id=str(uuid4()), source="Defender"),
        execution_id=str(uuid4()),
        payload=json.dumps(devices).encode(),
    )
    with db.cursor() as cur:
        authorize_connection(cur, defender)
    persist_devices(db, defender)
    with inventory(selected, binding) as (attempt, staged):
        persist_inventory(
            db, attempt, staged=staged, device_attempt_id=device.execution_id
        )
    with db.cursor() as cur:
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
    return attempt, binding, bundle


def test_persists_exact_bytes_replays_and_reader_sees_dated_status(db, evidence):
    attempt, binding, bundle = evidence
    raw = canonical(bundle).encode()
    saved = persist(db, attempt.execution_id, raw, binding=binding, origin="synthetic")
    assert not saved["replayed"]
    assert persist(db, attempt.execution_id, raw, binding=binding, origin="synthetic")[
        "replayed"
    ]
    with db.cursor() as cur:
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        cur.execute(
            "SELECT original_bytes FROM evidence_pipeline.windows_os_reviews WHERE id=%s",
            (saved["review_id"],),
        )
        assert bytes(cur.fetchone()[0]) == raw
        cur.execute(
            "SELECT identity_state,report->>'missing_state' FROM evidence_pipeline.current_windows_os_reviews WHERE review_id=%s",
            (saved["review_id"],),
        )
        assert cur.fetchone() == (
            "selected_from_compatible_retained_evidence",
            "none_reported",
        )
        cur.execute(
            "SELECT kb,status FROM evidence_pipeline.current_windows_os_update_status WHERE review_id=%s",
            (saved["review_id"],),
        )
        assert cur.fetchall() == [("KB5129195", "Observed installed")]
        cur.execute(
            "SELECT count(*) FROM evidence_pipeline.current_windows_os_findings WHERE review_id=%s",
            (saved["review_id"],),
        )
        assert cur.fetchone() == (0,)


def test_reader_cannot_insert_and_writer_cannot_change_evidence(db, evidence):
    attempt, binding, bundle = evidence
    saved = persist(
        db,
        attempt.execution_id,
        canonical(bundle).encode(),
        binding=binding,
        origin="synthetic",
    )
    with db.cursor() as cur:
        for role, sql in (
            (
                "tm_pipeline_writer",
                "DELETE FROM evidence_pipeline.windows_os_reviews WHERE id=%s",
            ),
            (
                "tm_mock_reader",
                "UPDATE evidence_pipeline.windows_os_reviews SET report='{}'::jsonb WHERE id=%s",
            ),
        ):
            cur.execute("SET LOCAL ROLE " + role)
            with pytest.raises(psycopg2.errors.InsufficientPrivilege), atomic(cur):
                cur.execute(sql, (saved["review_id"],))


def test_wrong_registered_inventory_origin_is_rejected_atomically(db, evidence):
    attempt, binding, bundle = evidence
    bundle["origin"] = "lab"
    with (
        pytest.raises(psycopg2.errors.RaiseException, match="exact registered"),
        db.cursor() as cur,
        atomic(cur),
    ):
        persist(
            db,
            attempt.execution_id,
            canonical(bundle).encode(),
            binding=binding,
            origin="lab",
        )
    with db.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM evidence_pipeline.windows_os_reviews WHERE inventory_attempt_id=%s",
            (attempt.execution_id,),
        )
        assert cur.fetchone() == (0,)


def test_unresolved_review_does_not_execute_json_null_as_an_array(db, evidence):
    attempt, binding, bundle = evidence
    change(bundle, "devices-0", lambda x: x["value"][1].update(osProcessor="arm64"))
    saved = persist(
        db,
        attempt.execution_id,
        canonical(bundle).encode(),
        binding=binding,
        origin="synthetic",
    )
    with db.cursor() as cur:
        cur.execute(
            "SELECT identity_state FROM evidence_pipeline.current_windows_os_reviews WHERE review_id=%s",
            (saved["review_id"],),
        )
        assert cur.fetchone() == ("unresolved",)
        for view in ("current_windows_os_update_status", "current_windows_os_findings"):
            cur.execute(
                f"SELECT count(*) FROM evidence_pipeline.{view} WHERE review_id=%s",
                (saved["review_id"],),
            )
            assert cur.fetchone() == (0,)


@pytest.mark.parametrize("timestamp", ["2099-01-01T00:00:00Z", None])
def test_unresolved_review_recency_must_match_retained_receipts(
    db, evidence, timestamp
):
    import hashlib
    from .os_update_evidence import evaluate

    attempt, binding, bundle = evidence
    saved = persist(
        db,
        attempt.execution_id,
        canonical(bundle).encode(),
        binding=binding,
        origin="synthetic",
    )
    change(bundle, "devices-0", lambda x: x["value"][1].update(osProcessor="arm64"))
    raw = canonical(bundle).encode()
    report = evaluate(raw, binding=binding, origin="synthetic")
    assert report["identity_state"] == "unresolved"
    report["provider_observed_at"] = timestamp
    with db.cursor() as cur:
        with (
            pytest.raises(
                psycopg2.errors.RaiseException, match="source-backed review recency"
            ),
            atomic(cur),
        ):
            cur.execute(
                "INSERT INTO evidence_pipeline.windows_os_reviews(id,inventory_attempt_id,input_fingerprint,engine_fingerprint,original_bytes,report) VALUES(%s,%s,%s,%s,%s,%s::jsonb)",
                (
                    str(uuid4()),
                    attempt.execution_id,
                    hashlib.sha256(raw).hexdigest(),
                    "0" * 64,
                    raw,
                    canonical(report),
                ),
            )
        cur.execute(
            "SELECT review_id::text,identity_state FROM evidence_pipeline.current_windows_os_reviews WHERE inventory_attempt_id=%s",
            (attempt.execution_id,),
        )
        assert cur.fetchall() == [
            (saved["review_id"], "selected_from_compatible_retained_evidence")
        ]


def test_current_os_review_authority_drift_is_rejected(db, evidence):
    with db.cursor() as cur:
        cur.execute("RESET ROLE")
        verify(cur)
        with atomic(cur):
            cur.execute(
                "GRANT DELETE ON evidence_pipeline.windows_os_reviews TO tm_pipeline_writer"
            )
            with pytest.raises(ValueError, match="schema/authority differs"):
                verify(cur)
            cur.execute(
                "REVOKE DELETE ON evidence_pipeline.windows_os_reviews FROM tm_pipeline_writer"
            )


def test_dashboard_queries_execute_under_reader(db, evidence):
    from pathlib import Path

    attempt, binding, bundle = evidence
    persist(
        db,
        attempt.execution_id,
        canonical(bundle).encode(),
        binding=binding,
        origin="synthetic",
    )
    text = (
        Path(__file__).resolve().parents[2] / "ui-engine/src/dashboard.json"
    ).read_text()
    with db.cursor() as cur:
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        blocks = [item for item in json.loads(text) if item["kind"] == "query"]
        assert blocks, "The dashboard must exercise at least one database query"
        charts = 0
        # Definitions are code-owned; verify query and chart contracts.
        # Verify the actual SQL and chart bindings, not a fixed page inventory.
        # Source identity/update semantics have independent synthetic view tests.
        for block in blocks:
            config = block.get("chart")
            query = block["sql"].replace("origin<>'synthetic'", "origin='synthetic'")
            try:
                cur.execute(query)
            except Exception as exc:
                raise AssertionError("Dashboard query failed: " + query) from exc
            assert cur.description is not None
            columns = {column.name for column in cur.description}
            if config:
                charts += 1
                assert isinstance(config["title"], str) and config["title"].strip()
                assert config["x"] in columns
                assert config["y"] in columns
            cur.fetchall()
        assert charts, "The dashboard must exercise database-backed chart bindings"


def test_report_cannot_invent_installed_updates(db, evidence):
    import hashlib
    from .os_update_evidence import evaluate

    attempt, binding, bundle = evidence
    raw = canonical(bundle).encode()
    report = evaluate(raw, binding=binding, origin="synthetic")
    report["installed_updates"][0]["kb"] = "KB9999999"
    with db.cursor() as cur:
        with (
            pytest.raises(
                psycopg2.errors.RaiseException, match="installation assertion"
            ),
            atomic(cur),
        ):
            cur.execute(
                "INSERT INTO evidence_pipeline.windows_os_reviews(id,inventory_attempt_id,input_fingerprint,engine_fingerprint,original_bytes,report) VALUES(%s,%s,%s,%s,%s,%s::jsonb)",
                (
                    str(uuid4()),
                    attempt.execution_id,
                    hashlib.sha256(raw).hexdigest(),
                    "0" * 64,
                    raw,
                    canonical(report),
                ),
            )


@pytest.mark.parametrize(
    "product",
    [
        "Windows 11 Version 25H2 for x64-based Systems",
        "Windows 11 Version 25H2 for ARM64-based Systems",
        "Windows 11 Version 24H2 for x64-based Systems",
    ],
)
def test_replacement_paths_require_exact_product_release_and_architecture(
    db, evidence, snapshot, product
):
    from standalone.evidence_pipeline.persistence.exposure_store import persist_exposure
    from standalone.evidence_pipeline.persistence.public_store import persist_public
    from standalone.evidence_pipeline.test_cvrf_store import (
        snapshot as advisory_snapshot,
    )

    attempt, binding, bundle = evidence
    bundle["queried_kbs"] = ["KB9999991"]
    change(bundle, "installed", lambda x: x["rows"][0].update(HotFixID="KB9999991"))
    saved = persist(
        db,
        attempt.execution_id,
        canonical(bundle).encode(),
        binding=binding,
        origin="synthetic",
    )
    advisory = advisory_snapshot()
    advisory = replace(
        advisory,
        payload=advisory.payload.replace(
            b"Synthetic product release A", product.encode()
        ),
    )
    with db.cursor() as cur:
        cur.execute("RESET ROLE")
        cur.execute(
            "SELECT c.id::text,a.id::text FROM evidence.source_connections c JOIN evidence.microsoft_tenants t ON t.id=c.tenant_id JOIN evidence.collection_attempts a ON a.connection_id=c.id WHERE t.external_tenant_id=%s AND c.source_name='Defender' AND c.input_kind='devices'",
            (binding.tenant_id,),
        )
        device_connection, device_attempt = cur.fetchone()
        missing = replace(
            snapshot,
            scope=replace(
                snapshot.scope,
                source="Defender",
                input_kind="missing_patches",
                tenant_id=binding.tenant_id,
                connection_id=str(uuid4()),
            ),
            execution_id=str(uuid4()),
            payload=json.dumps(
                [
                    {
                        "machineId": "a" * 40,
                        "id": "9999990",
                        "productsNames": ["windows_11"],
                    }
                ]
            ).encode(),
        )
        authorize_connection(cur, missing)
        cur.execute(
            "INSERT INTO evidence_pipeline.input_device_scopes VALUES(%s,%s)",
            (missing.scope.connection_id, device_connection),
        )
        authorize_connection(cur, advisory)
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
    persist_exposure(db, missing, device_attempt)
    persist_public(db, advisory)
    with db.cursor() as cur:
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        cur.execute(
            "SELECT status,observed_installed_replacement FROM evidence_pipeline.current_windows_os_update_status WHERE review_id=%s AND kb='KB9999990'",
            (saved["review_id"],),
        )
        row = cur.fetchone()
        if product == "Windows 11 Version 25H2 for x64-based Systems":
            assert row == (
                "Historical update replaced by observed installed update",
                "KB9999991",
            )
        else:
            assert row == ("Historical candidate; current applicability unknown", None)


def test_competing_same_time_reviews_block_selection(db, evidence):
    attempt, binding, bundle = evidence
    persist(
        db,
        attempt.execution_id,
        canonical(bundle).encode(),
        binding=binding,
        origin="synthetic",
    )
    # Different evidence at the same times cannot be silently tie-broken by UUID.
    change(
        bundle, "devices-0", lambda x: x["value"][1].update(isPotentialDuplication=True)
    )
    persist(
        db,
        attempt.execution_id,
        canonical(bundle).encode(),
        binding=binding,
        origin="synthetic",
    )
    with db.cursor() as cur:
        cur.execute(
            "SELECT DISTINCT identity_state FROM evidence_pipeline.current_windows_os_reviews WHERE inventory_attempt_id=%s",
            (attempt.execution_id,),
        )
        assert cur.fetchall() == [("conflicting_reviews",)]
        cur.execute(
            "SELECT count(*) FROM evidence_pipeline.current_windows_os_findings f JOIN evidence_pipeline.current_windows_os_reviews r USING(review_id) WHERE r.inventory_attempt_id=%s",
            (attempt.execution_id,),
        )
        assert cur.fetchone() == (0,)


def test_source_reported_missing_is_preserved_separately_from_installation(
    db, evidence
):
    attempt, binding, bundle = evidence
    change(
        bundle,
        "current-missing-kbs-0",
        lambda x: x["value"].append({"id": "5129195", "productsNames": ["windows_11"]}),
    )
    saved = persist(
        db,
        attempt.execution_id,
        canonical(bundle).encode(),
        binding=binding,
        origin="synthetic",
    )
    with db.cursor() as cur:
        cur.execute(
            "SELECT status FROM evidence_pipeline.current_windows_os_update_status WHERE review_id=%s",
            (saved["review_id"],),
        )
        assert {r[0] for r in cur.fetchall()} == {
            "Observed installed",
            "Source reported missing; applicability not independently verified",
        }


def test_new_native_inventory_blocks_old_review_without_deleting_history(
    db, evidence, configured
):
    import io
    from .snapshot import InventoryAttempt
    from .staging import stage
    from .test_contract import sample as inventory_sample

    attempt, binding, bundle = evidence
    device, selected, _ = configured
    saved = persist(
        db,
        attempt.execution_id,
        canonical(bundle).encode(),
        binding=binding,
        origin="synthetic",
    )
    payload = inventory_sample()
    payload.update(
        machine_guid=binding.machine_guid,
        tenant_id=binding.tenant_id,
        device_id=binding.device_id,
        started_at="2026-09-22T01:00:00Z",
        finished_at="2026-09-22T01:00:01Z",
    )
    with stage(io.BytesIO(canonical(payload).encode()), binding) as staged:
        newer = InventoryAttempt.from_staged(selected, str(uuid4()), staged)
        persist_inventory(
            db, newer, staged=staged, device_attempt_id=device.execution_id
        )
    with db.cursor() as cur:
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        cur.execute(
            "SELECT identity_state FROM evidence_pipeline.current_windows_os_reviews WHERE review_id=%s",
            (saved["review_id"],),
        )
        assert cur.fetchone() == ("newer_inventory_requires_review",)
        for view in ("current_windows_os_findings", "current_windows_os_update_status"):
            cur.execute(
                f"SELECT count(*) FROM evidence_pipeline.{view} WHERE review_id=%s",
                (saved["review_id"],),
            )
            assert cur.fetchone() == (0,)
        cur.execute(
            "SELECT identity_state FROM evidence_pipeline.windows_os_review_history WHERE review_id=%s",
            (saved["review_id"],),
        )
        assert cur.fetchone() == ("selected_from_compatible_retained_evidence",)


@pytest.mark.parametrize(
    "forgery", ["resolved_without_identity", "historical_identity"]
)
def test_restricted_writer_cannot_forge_resolved_identity(db, evidence, forgery):
    import hashlib
    from .os_update_evidence import evaluate
    from .test_os_update_evidence import OLD

    attempt, binding, bundle = evidence
    if forgery == "resolved_without_identity":
        change(bundle, "devices-0", lambda x: x["value"][1].update(osProcessor="arm64"))
    raw = canonical(bundle).encode()
    report = evaluate(raw, binding=binding, origin="synthetic")
    if forgery == "resolved_without_identity":
        assert report["selected_native_device_id"] is None
        report.update(
            identity_state="selected_from_compatible_retained_evidence",
            missing_state="none_reported",
            missing_updates=[],
            device_findings=[],
        )
    else:
        report["selected_native_device_id"] = OLD
        report["device_findings"] = json.loads(
            bundle["sources"]["vulnerabilities-0"]["text"]
        )["value"]
    with db.cursor() as cur:
        with pytest.raises(psycopg2.errors.RaiseException), atomic(cur):
            cur.execute(
                "INSERT INTO evidence_pipeline.windows_os_reviews(id,inventory_attempt_id,input_fingerprint,engine_fingerprint,original_bytes,report) VALUES(%s,%s,%s,%s,%s,%s::jsonb)",
                (
                    str(uuid4()),
                    attempt.execution_id,
                    hashlib.sha256(raw).hexdigest(),
                    "0" * 64,
                    raw,
                    canonical(report),
                ),
            )


@pytest.mark.parametrize(
    "defect",
    [
        "architecture",
        "competing_identity",
        "endpoint",
        "incomplete_export",
        "stale_provider",
        "duplicate_flag",
    ],
)
def test_resolved_report_requires_original_compatible_sources(db, evidence, defect):
    import hashlib
    from .os_update_evidence import evaluate
    from .test_os_update_evidence import OLD

    attempt, binding, bundle = evidence
    report = evaluate(canonical(bundle).encode(), binding=binding, origin="synthetic")
    if defect == "architecture":
        change(bundle, "devices-0", lambda x: x["value"][1].update(osProcessor="arm64"))
    elif defect == "duplicate_flag":
        change(
            bundle,
            "devices-0",
            lambda x: x["value"][1].update(isPotentialDuplication=True),
        )
    elif defect == "stale_provider":
        change(
            bundle,
            "devices-0",
            lambda x: x["value"][1].update(lastSeen="2026-09-17T01:00:00Z"),
        )
    elif defect == "competing_identity":
        change(
            bundle,
            "devices-0",
            lambda x: x["value"][0].update(lastSeen="2026-09-21T01:00:00Z"),
        )
    elif defect == "endpoint":
        change(
            bundle,
            "requests",
            lambda x: x[3]["pages"][0].update(
                url=f"https://api.security.microsoft.com/api/machines/{OLD}/getmissingkbs"
            ),
        )
    else:
        change(bundle, "requests", lambda x: x[3].update(complete=False))
    # Preserve internally consistent hashes: rejection must concern the source
    # meaning, not merely the intentionally changed document's checksum.
    for name, value in bundle["sources"].items():
        report["sources"][name]["sha256"] = value["sha256"]
    raw = canonical(bundle).encode()
    with db.cursor() as cur:
        with (
            pytest.raises(
                psycopg2.errors.RaiseException, match="OS identity authority"
            ),
            atomic(cur),
        ):
            cur.execute(
                "INSERT INTO evidence_pipeline.windows_os_reviews(id,inventory_attempt_id,input_fingerprint,engine_fingerprint,original_bytes,report) VALUES(%s,%s,%s,%s,%s,%s::jsonb)",
                (
                    str(uuid4()),
                    attempt.execution_id,
                    hashlib.sha256(raw).hexdigest(),
                    "0" * 64,
                    raw,
                    canonical(report),
                ),
            )


@pytest.mark.parametrize("defect", ["missing_revision", "stale_installation"])
def test_direct_writer_requires_complete_compatible_native_facts(db, evidence, defect):
    import hashlib
    from .os_update_evidence import evaluate

    attempt, binding, bundle = evidence
    report = evaluate(canonical(bundle).encode(), binding=binding, origin="synthetic")
    if defect == "missing_revision":
        change(bundle, "native", lambda x: x.pop("ubr"))
        change(bundle, "installed", lambda x: x["identity"].pop("ubr"))
        change(
            bundle,
            "software-inventory-0",
            lambda x: x["value"][1].pop("softwareVersion"),
        )
        report["windows_version"] = None
        report["providers"][1]["windows_versions"] = [None]
    else:
        change(
            bundle, "installed", lambda x: x.update(observed_at="2000-01-01T00:00:00Z")
        )
        report["installed_updates"][0]["observed_at"] = "2000-01-01T00:00:00Z"
    for name, value in bundle["sources"].items():
        report["sources"][name]["sha256"] = value["sha256"]
    raw = canonical(bundle).encode()
    with db.cursor() as cur:
        with pytest.raises(psycopg2.errors.RaiseException), atomic(cur):
            cur.execute(
                "INSERT INTO evidence_pipeline.windows_os_reviews(id,inventory_attempt_id,input_fingerprint,engine_fingerprint,original_bytes,report) VALUES(%s,%s,%s,%s,%s,%s::jsonb)",
                (
                    str(uuid4()),
                    attempt.execution_id,
                    hashlib.sha256(raw).hexdigest(),
                    "0" * 64,
                    raw,
                    canonical(report),
                ),
            )


@pytest.mark.parametrize(
    "version", ["pipeline-windows-os-native-facts-v113", "unknown", None]
)
def test_os_review_writer_refuses_unsupported_version(db, evidence, version):
    from .test_store import unsupported_version

    attempt, binding, bundle = evidence
    with unsupported_version(db, version):
        persist(
            db,
            attempt.execution_id,
            canonical(bundle).encode(),
            binding=binding,
            origin="synthetic",
        )
