"""Synthetic response boundaries for device-scoped missing patches."""

from dataclasses import replace
import json
from types import SimpleNamespace as NS
from uuid import uuid4

import pytest

from microsoft_evidence.missing_patch_pipeline import collect_missing_patches
from microsoft_evidence.pipeline import connection_scope
from microsoft_evidence.source_registry import SOURCE_INPUTS
from standalone.evidence_pipeline.contracts import Snapshot, SourceScope
from tests.test_microsoft_live_authority import NOW


def setup_collection(records=None):
    scope = SourceScope(
        str(uuid4()),
        "Defender",
        "missing_patches",
        "test",
        "lab",
        "Explicitly synthetic test",
        str(uuid4()),
    )
    device_scope = replace(scope, connection_id=str(uuid4()), input_kind="devices")
    devices = Snapshot(
        device_scope,
        str(uuid4()),
        NOW,
        NOW,
        "success",
        True,
        json.dumps([{"id": "device-a"}, {"id": "device-b"}]).encode(),
    )
    source = next(s for s in SOURCE_INPUTS if s.input_id == "ms-defender-missing-kb-v1")
    result = NS(
        input_id=source.input_id,
        source_contract_id=source.source_contract_id,
        pages=[NS(records=records if records is not None else [{"id": "KB1"}])],
    )
    calls = []

    def authority(device):
        return NS(
            scope=connection_scope(scope),
            endpoint=NS(path_template=f"/api/machines/{device}/getmissingkbs"),
        ), object()

    def collect(**kwargs):
        calls.append(kwargs)
        return result

    return (
        dict(
            scope=scope,
            execution_id=str(uuid4()),
            device_snapshot=devices,
            authority_for_device=authority,
            transport=NS(collect=collect),
            now=lambda: NOW,
        ),
        calls,
        result,
    )


def test_routes_attach_device_identity_and_preserve_unknowns_without_cve_links():
    args, calls, _ = setup_collection()
    snapshot = collect_missing_patches(**args)
    assert snapshot.records() == [
        {"id": "KB1", "machineId": "device-a"},
        {"id": "KB1", "machineId": "device-b"},
    ]
    assert len(calls) == 2
    assert all("machineId" not in c["allowed_record_fields"] for c in calls)


@pytest.mark.parametrize("missing_id", [False, True])
def test_full_http_response_projects_unretained_fields_but_requires_id(missing_id):
    import httpx
    from microsoft_evidence.transport import (
        MicrosoftHttpTransport,
        MicrosoftTransportError,
    )
    from tests.test_microsoft_live_authority import _live_prepared
    from tests.test_microsoft_transport import _lease

    args, _, _ = setup_collection()

    def authority(device):
        prepared = _live_prepared(
            scope=connection_scope(args["scope"]),
            source_input=(
                "defender",
                f"/api/machines/{device}/getmissingkbs",
                "https://api.security.microsoft.com",
                ("Software.Read.All", "Vulnerability.Read.All"),
            ),
        )
        return prepared, _lease(prepared)

    wire = {"osBuild": "synthetic-unretained-build", "cveAddressed": 2}
    if not missing_id:
        wire["id"] = "KB-SYNTHETIC"
    args["authority_for_device"] = authority
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(200, json={"value": [wire]})
        )
    ) as client:
        args["transport"] = MicrosoftHttpTransport(client=client, now=lambda: NOW)
        if missing_id:
            with pytest.raises(MicrosoftTransportError, match="schema"):
                collect_missing_patches(**args)
        else:
            snapshot = collect_missing_patches(**args)
            assert b"osBuild" not in snapshot.payload
            assert len(snapshot.records()) == 2
            assert all(row["cveAddressed"] == 2 for row in snapshot.records())


@pytest.mark.parametrize(
    "field,value",
    [
        ("input_id", "different"),
        ("source_contract_id", "different"),
        ("pages", []),
    ],
)
def test_contract_mismatch_rejects_entire_collection(field, value):
    args, _, result = setup_collection()
    setattr(result, field, value)
    with pytest.raises(ValueError, match="contract"):
        collect_missing_patches(**args)


@pytest.mark.parametrize(
    "bad",
    [
        [{"id": "KB1", "machineId": "other"}],
        [{"id": "KB1", "cveAddressed": True}],
        [{"id": "KB1"}, {"id": "KB1"}],
    ],
)
def test_injected_identity_invalid_count_and_duplicate_rejected(bad):
    args, _, _ = setup_collection(bad)
    with pytest.raises(ValueError):
        collect_missing_patches(**args)


@pytest.mark.parametrize("mismatch", ["route", "scope"])
def test_authority_mismatch_rejected_before_transport(mismatch):
    args, calls, _ = setup_collection()
    original = args["authority_for_device"]

    def bad(device):
        prepared, token = original(device)
        if mismatch == "route":
            prepared.endpoint.path_template = "/api/machines/other/getmissingkbs"
        else:
            prepared.scope = connection_scope(
                replace(args["scope"], tenant_id=str(uuid4()))
            )
        return prepared, token

    args["authority_for_device"] = bad
    with pytest.raises(ValueError):
        collect_missing_patches(**args)
    assert calls == []


def test_empty_responses_are_complete_but_still_query_every_device():
    args, calls, _ = setup_collection([])
    assert collect_missing_patches(**args).records() == []
    assert len(calls) == 2


def test_failure_on_second_device_cannot_return_partial_snapshot():
    args, calls, _ = setup_collection()
    original = args["transport"].collect

    def failing(**kwargs):
        if calls:
            raise RuntimeError("synthetic transport failure")
        return original(**kwargs)

    args["transport"].collect = failing
    with pytest.raises(RuntimeError):
        collect_missing_patches(**args)


def test_cancelled_before_collection_makes_no_requests():
    args, calls, _ = setup_collection()
    with pytest.raises(ValueError, match="cancelled"):
        collect_missing_patches(**args, cancelled=lambda: True)
    assert calls == []


def test_real_transport_accepts_provider_id_with_verified_synthetic_lease():
    import httpx
    from microsoft_evidence.transport import MicrosoftHttpTransport
    from tests.test_microsoft_live_authority import _live_prepared
    from tests.test_microsoft_transport import _lease

    args, _, _ = setup_collection()
    requests = []

    def authority(device):
        prepared = _live_prepared(
            scope=connection_scope(args["scope"]),
            source_input=(
                "defender",
                f"/api/machines/{device}/getmissingkbs",
                "https://api.security.microsoft.com",
                ("Software.Read.All", "Vulnerability.Read.All"),
            ),
        )
        return prepared, _lease(prepared)

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={"value": [{"id": "KB1", "cveAddressed": 0}]})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        args.update(
            authority_for_device=authority,
            transport=MicrosoftHttpTransport(client=client, now=lambda: NOW),
        )
        snapshot = collect_missing_patches(**args)
    assert len(requests) == 2
    assert snapshot.records()[0]["cveAddressed"] == 0


@pytest.mark.parametrize("bound", ["MAX_RECORDS"])
def test_aggregate_response_is_bounded(monkeypatch, bound):
    import microsoft_evidence.missing_patch_pipeline as pipeline

    args, _, _ = setup_collection()
    monkeypatch.setattr(pipeline, bound, 1)
    with pytest.raises(ValueError, match="bounds"):
        collect_missing_patches(**args)


def test_durable_retry_never_recollects_and_keeps_device_binding(tmp_path, monkeypatch):
    from microsoft_evidence.missing_patch_pipeline import (
        collect_and_ingest_missing_patches,
    )
    from standalone.evidence_pipeline import commands

    args, calls, _ = setup_collection()
    imported = []
    monkeypatch.setattr(
        commands,
        "ingest_exposure",
        lambda snapshot, device: imported.append((snapshot, device)) or snapshot,
    )
    first = collect_and_ingest_missing_patches(**args, root=tmp_path)
    assert len(calls) == 2
    second = collect_and_ingest_missing_patches(**args, root=tmp_path)
    assert first == second
    assert len(calls) == 2
    args["device_snapshot"] = replace(
        args["device_snapshot"], execution_id=str(uuid4())
    )
    with pytest.raises(ValueError):
        collect_and_ingest_missing_patches(**args, root=tmp_path)
    assert len(imported) == 2


def test_failure_bundle_uses_safe_code_without_partial_rows(tmp_path, monkeypatch):
    from microsoft_evidence.missing_patch_pipeline import (
        collect_and_ingest_missing_patches,
    )
    from microsoft_evidence.transport import MicrosoftTransportError
    from standalone.evidence_pipeline import commands

    args, _, _ = setup_collection()
    monkeypatch.setattr(commands, "ingest_exposure", lambda snapshot, device: snapshot)

    def failing(**kwargs):
        raise MicrosoftTransportError("synthetic provider detail that must not persist")

    args["transport"].collect = failing
    result = collect_and_ingest_missing_patches(**args, root=tmp_path)
    assert not result.complete and result.outcome == "failure"
    assert result.payload == b"" and result.error_code == "microsoft_collection_failed"
