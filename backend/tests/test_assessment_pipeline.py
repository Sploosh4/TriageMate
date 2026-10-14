"""Synthetic baseline/delta paging, isolation and immutable retry context."""

from dataclasses import replace
from datetime import timedelta
from uuid import uuid4

import httpx
import pytest

from microsoft_evidence.assessment_pipeline import (
    INPUTS,
    collect_assessments,
    prepare_assessments,
)
from microsoft_evidence.pipeline import connection_scope
from microsoft_evidence.transport import MicrosoftHttpTransport, MicrosoftTransportError
from standalone.evidence_pipeline.contracts import Snapshot
from tests.test_microsoft_pipeline import scope
from tests.test_microsoft_live_authority import NOW, _live_prepared
from tests.test_microsoft_transport import _lease


def inputs(kind):
    device_scope = replace(scope(), source="Defender")
    device = Snapshot(
        device_scope,
        str(uuid4()),
        NOW,
        NOW,
        "success",
        True,
        b'[{"id":"synthetic-device"}]',
    )
    source = replace(device_scope, connection_id=str(uuid4()), input_kind=kind)
    prepared = _live_prepared(
        scope=connection_scope(source),
        source_input=(
            "defender",
            INPUTS[kind][1],
            "https://api.security.microsoft.com",
            ("Vulnerability.Read.All",),
        ),
    )
    prepared = prepared.model_copy(
        update={
            "endpoint": prepared.endpoint.model_copy(
                update={
                    "allowed_query_parameter_names": ("pageSize", "sinceTime"),
                    "paging_query_parameter_names": (
                        "pageSize",
                        "pagesize",
                        "sinceTime",
                        "sincetime",
                        "$skiptoken",
                    ),
                }
            )
        }
    )
    return source, device, prepared


@pytest.mark.parametrize("kind", INPUTS)
def test_export_pages_use_pagesize_not_truncating_top(kind):
    source, device, prepared = inputs(kind)
    calls = []

    def handler(request):
        calls.append(request)
        assert "$top" not in request.url.params
        if len(calls) == 1:
            record = {
                "id": "synthetic-instance",
                "deviceId": "synthetic-device",
                "softwareVendor": "Synthetic vendor",
                "softwareName": "Synthetic app",
                "softwareVersion": "1",
                "cveId": None,
            }
            if kind == "vulnerability_events":
                record.update(status="Fixed", eventTimestamp="2026-08-25 06:00:00")
            return httpx.Response(
                200,
                json={
                    "value": [record],
                    "@odata.nextLink": "https://api.security.microsoft.com"
                    + INPUTS[kind][1]
                    + "?pagesize=1000&$skiptoken=synthetic",
                },
            )
        return httpx.Response(200, json={"value": []})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        snapshot = collect_assessments(
            scope=source,
            execution_id=str(uuid4()),
            device_snapshot=device,
            prepared=prepared,
            token=_lease(prepared),
            transport=MicrosoftHttpTransport(client=client, now=lambda: NOW),
            since=NOW - timedelta(hours=6) if kind == "vulnerability_events" else None,
            now=lambda: NOW,
        )
    assert snapshot.complete and len(snapshot.records()) == 1 and len(calls) == 2


def test_expired_delta_window_does_not_make_network_request():
    source, device, prepared = inputs("vulnerability_events")
    with pytest.raises(ValueError, match="fresh baseline"):
        collect_assessments(
            scope=source,
            execution_id=str(uuid4()),
            device_snapshot=device,
            prepared=prepared,
            token=None,
            transport=None,
            since=NOW - timedelta(days=15),
            now=lambda: NOW,
        )


def test_replay_preserves_checkpoint_and_never_reacquires_authority(tmp_path):
    source, device, _ = inputs("vulnerability_events")
    since = NOW - timedelta(hours=6)
    execution = str(uuid4())
    snapshot = Snapshot(source, execution, NOW, NOW, "success", True, b"[]")
    args = dict(
        scope=source,
        execution_id=execution,
        device_snapshot=device,
        root=tmp_path,
        since=since,
        now=lambda: NOW,
    )
    assert prepare_assessments(**args, fetch=lambda: snapshot) == snapshot
    assert (
        prepare_assessments(
            **args, fetch=lambda: pytest.fail("Refetched saved execution")
        )
        == snapshot
    )
    with pytest.raises(ValueError, match="binding"):
        prepare_assessments(
            **{**args, "since": since - timedelta(hours=1)},
            fetch=lambda: pytest.fail("Refetched changed context"),
        )


def test_transport_failure_is_saved_without_success_or_checkpoint_advance(tmp_path):
    source, device, _ = inputs("vulnerability_events")

    def fail():
        raise MicrosoftTransportError("Synthetic private error text must not persist")

    snapshot = prepare_assessments(
        scope=source,
        execution_id=str(uuid4()),
        device_snapshot=device,
        root=tmp_path,
        since=NOW - timedelta(hours=6),
        fetch=fail,
        now=lambda: NOW,
    )
    assert not snapshot.complete and snapshot.payload == b""
    assert snapshot.error_code == "microsoft_collection_failed"


@pytest.mark.parametrize("kind", INPUTS)
@pytest.mark.parametrize("unexpected", [False, True])
def test_assessment_cannot_expand_bound_device_allowlist(kind, unexpected):
    import json

    source, device, prepared = inputs(kind)
    device = replace(
        device,
        scope=replace(
            device.scope, scope_reference="allowed-native-device-ids:" + "a" * 40
        ),
        payload=json.dumps([{"id": "a" * 40}]).encode(),
    )
    record = {
        "id": "synthetic-instance",
        "deviceId": ("b" if unexpected else "a") * 40,
        "softwareVendor": "Synthetic vendor",
        "softwareName": "Synthetic app",
        "softwareVersion": "1",
    }
    if kind == "vulnerability_events":
        record.update(status="New", eventTimestamp="2026-08-25 06:00:00")
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json={"value": [record]})
        )
    ) as client:

        def collect():
            return collect_assessments(
                scope=source,
                execution_id=str(uuid4()),
                device_snapshot=device,
                prepared=prepared,
                token=_lease(prepared),
                transport=MicrosoftHttpTransport(client=client, now=lambda: NOW),
                since=NOW - timedelta(hours=6)
                if kind == "vulnerability_events"
                else None,
                now=lambda: NOW,
            )

        if unexpected:
            with pytest.raises(ValueError, match="explicit device allowlist"):
                collect()
        else:
            assert len(collect().records()) == 1
