"""Synthetic direct recommendation/device collection, authority and replay."""

from dataclasses import replace
from uuid import uuid4

import httpx
import pytest

from microsoft_evidence.recommendation_pipeline import (
    collect_recommendations,
    PATH,
    DEVICE_PATH,
)
from microsoft_evidence.pipeline import connection_scope, device_binding
from microsoft_evidence.transport import MicrosoftHttpTransport, MicrosoftTransportError
from standalone.evidence_pipeline.contracts import Snapshot
from standalone.evidence_pipeline.collection.snapshot_bundle import (
    prepare_recommendations,
)
from tests.test_microsoft_pipeline import scope
from tests.test_microsoft_live_authority import NOW, _live_prepared
from tests.test_microsoft_transport import _lease


def prepared(source, path):
    value = _live_prepared(
        scope=connection_scope(source),
        source_input=(
            "defender",
            path,
            "https://api.security.microsoft.com",
            ("SecurityRecommendation.Read.All",),
        ),
    )
    return value.model_copy(
        update={
            "endpoint": value.endpoint.model_copy(
                update={
                    "allowed_query_parameter_names": ("$top", "$skip"),
                    "paging_query_parameter_names": ("$top", "$skip", "$skiptoken"),
                }
            )
        }
    )


def collect(handler):
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
    source = replace(
        device_scope, connection_id=str(uuid4()), input_kind="recommendations"
    )
    context = prepared(source, PATH)

    def authority(key):
        value = prepared(source, DEVICE_PATH.replace("{id}", key))
        return value, _lease(value)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = collect_recommendations(
            scope=source,
            execution_id=str(uuid4()),
            device_snapshot=device,
            prepared=context,
            token=_lease(context),
            transport=MicrosoftHttpTransport(
                client=client, now=lambda: NOW, max_retries=0
            ),
            association_authority=authority,
            now=lambda: NOW,
        )
    return result, device


def test_advice_and_all_device_pages_are_one_durable_snapshot(tmp_path):
    calls = []

    def handler(request):
        calls.append(request)
        if request.url.path == PATH:
            return httpx.Response(
                200,
                json={
                    "value": [
                        {
                            "id": "synthetic-advice",
                            "recommendationName": "Synthetic advice",
                            "unretained": "discard",
                        }
                    ]
                },
            )
        if "$skiptoken" not in request.url.params:
            return httpx.Response(
                200,
                json={
                    "value": [{"id": "synthetic-device", "computerDnsName": "discard"}],
                    "@odata.nextLink": "https://api.security.microsoft.com"
                    + request.url.path
                    + "?$skiptoken=synthetic",
                },
            )
        return httpx.Response(200, json={"value": []})

    result, device = collect(handler)
    snapshot, links = result
    assert (
        len(calls) == 3
        and b"discard" not in snapshot.payload
        and b"synthetic-device" in links
    )
    args = dict(
        scope=snapshot.scope,
        execution_id=snapshot.execution_id,
        root=tmp_path,
        binding=device_binding(snapshot.scope, device, source="Defender"),
    )
    assert prepare_recommendations(**args, collect=lambda: result) == result
    assert (
        prepare_recommendations(
            **args, collect=lambda: pytest.fail("Refetched saved associations")
        )
        == result
    )


def test_failed_association_never_returns_complete_advice():
    def handler(request):
        return (
            httpx.Response(
                200,
                json={
                    "value": [
                        {
                            "id": "synthetic-advice",
                            "recommendationName": "Synthetic advice",
                        }
                    ]
                },
            )
            if request.url.path == PATH
            else httpx.Response(503)
        )

    with pytest.raises(MicrosoftTransportError):
        collect(handler)


def test_unknown_device_is_not_silently_attached():
    def handler(request):
        records = (
            [{"id": "synthetic-advice", "recommendationName": "Synthetic advice"}]
            if request.url.path == PATH
            else [{"id": "unknown"}]
        )
        return httpx.Response(200, json={"value": records})

    (snapshot, links), device = collect(handler)
    assert snapshot.complete and links == b'{"synthetic-advice":["unknown"]}'
    assert b"unknown" not in device.payload


def test_failed_pair_is_durable_and_replay_does_not_collect(tmp_path, monkeypatch):
    from microsoft_evidence.recommendation_pipeline import (
        collect_and_ingest_recommendations,
    )
    import standalone.evidence_pipeline.recommendation_commands as commands

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
    source = replace(
        device_scope, connection_id=str(uuid4()), input_kind="recommendations"
    )
    saved = []
    monkeypatch.setattr(commands, "ingest", lambda *args: saved.append(args) or args[0])
    calls = []

    def failed():
        calls.append(1)
        raise ValueError("synthetic partial association failure")

    args = dict(
        scope=source,
        execution_id=str(uuid4()),
        root=tmp_path,
        device_snapshot=device,
        collect=failed,
        now=lambda: NOW,
    )
    first = collect_and_ingest_recommendations(**args)
    second = collect_and_ingest_recommendations(**args)
    assert first == second and not first.complete and first.payload == b""
    assert first.error_code == "invalid_microsoft_collection" and calls == [1]
    assert saved[0][1:] == (device.execution_id, None)


@pytest.mark.parametrize("source_id", (".", "..", "with/slash"))
def test_recommendation_identity_cannot_change_the_association_route(source_id):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(
            200,
            json={
                "value": [{"id": source_id, "recommendationName": "Synthetic advice"}]
            },
        )

    with pytest.raises(ValueError, match="unsafe"):
        collect(handler)
    assert len(calls) == 1


@pytest.mark.parametrize(
    "damage", [None, "wrong_device", "continuation", "duplicate", "saturated"]
)
def test_selected_device_recommendations_never_enumerate_other_devices(damage):
    import json
    from microsoft_evidence.recommendation_pipeline import device_recommendations_path

    native = "a" * 40
    device_scope = replace(scope(), source="Defender")
    device = Snapshot(
        device_scope,
        str(uuid4()),
        NOW,
        NOW,
        "success",
        True,
        json.dumps([{"id": "b" * 40 if damage == "wrong_device" else native}]).encode(),
    )
    source = replace(
        device_scope,
        connection_id=str(uuid4()),
        input_kind="recommendations",
        scope_reference="native-device-id:" + native,
    )
    path = device_recommendations_path(native)
    context = prepared(source, path)
    calls = []

    def handler(request):
        calls.append(request)
        assert request.url.path == path and not request.url.query
        row = {
            "id": "synthetic-recommendation",
            "recommendationName": "Synthetic advice",
            "totalMachineCount": 23,
            "exposedMachinesCount": 12,
        }
        body = {"value": [row, row] if damage == "duplicate" else [row]}
        if damage == "saturated":
            body["value"] = [dict(row, id=f"synthetic-{i}") for i in range(10000)]
        if damage == "continuation":
            body["@odata.nextLink"] = "https://api.security.microsoft.com" + PATH
        return httpx.Response(200, json=body)

    def forbidden_authority(_):
        raise AssertionError("Scoped advice must not enumerate machine references")

    def run():
        with httpx.Client(transport=httpx.MockTransport(handler)) as client:
            return collect_recommendations(
                scope=source,
                execution_id=str(uuid4()),
                device_snapshot=device,
                prepared=context,
                token=_lease(context),
                transport=MicrosoftHttpTransport(
                    client=client, now=lambda: NOW, max_retries=0
                ),
                association_authority=forbidden_authority,
                now=lambda: NOW,
            )

    if damage:
        with pytest.raises((ValueError, MicrosoftTransportError)):
            run()
        assert len(calls) == (0 if damage == "wrong_device" else 1)
    else:
        snapshot, associations = run()
        assert json.loads(associations) == {"synthetic-recommendation": [native]}
        assert json.loads(snapshot.payload)[0]["totalMachineCount"] == 23
        assert len(calls) == 1
