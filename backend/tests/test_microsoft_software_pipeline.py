"""Synthetic combined Intune collection retry and association validation."""

from dataclasses import replace
import json
from uuid import uuid4

import pytest

from microsoft_evidence.pipeline import collect_and_ingest_software
from standalone.evidence_pipeline import commands
from standalone.evidence_pipeline.contracts import Snapshot
from tests.test_microsoft_pipeline import scope
from tests.test_microsoft_live_authority import NOW


@pytest.fixture
def inputs(tmp_path):
    source = replace(scope(), source="Intune")
    device_id = str(uuid4())
    device = Snapshot(
        source,
        str(uuid4()),
        NOW,
        NOW,
        "success",
        True,
        json.dumps([{"id": device_id}]).encode(),
    )
    source = replace(source, input_kind="software", connection_id=str(uuid4()))
    app = {
        "id": "synthetic-app",
        "displayName": "Synthetic application",
        "deviceCount": 1,
    }
    snapshot = Snapshot(
        source, str(uuid4()), NOW, NOW, "success", True, json.dumps([app]).encode()
    )
    links = json.dumps({"synthetic-app": [device_id]}).encode()
    root = tmp_path / "bundles"
    root.mkdir(mode=0o700)
    return (
        dict(
            scope=source,
            execution_id=snapshot.execution_id,
            root=root,
            device_snapshot=device,
            now=lambda: NOW,
        ),
        snapshot,
        links,
    )


def test_uncertain_import_replays_both_inputs(inputs, monkeypatch):
    args, snapshot, links = inputs
    received = []

    def uncertain(*values):
        received.append(values)
        raise RuntimeError("simulated lost commit acknowledgement")

    monkeypatch.setattr(commands, "ingest_exposure", uncertain)
    with pytest.raises(RuntimeError):
        collect_and_ingest_software(**args, collect=lambda: (snapshot, links))
    monkeypatch.setattr(
        commands, "ingest_exposure", lambda *values: received.append(values) or "ok"
    )
    assert (
        collect_and_ingest_software(
            **args, collect=lambda: pytest.fail("Recollected saved inputs")
        )
        == "ok"
    )
    assert received == [(snapshot, args["device_snapshot"].execution_id, links)] * 2
    with pytest.raises(ValueError, match="binding differs"):
        collect_and_ingest_software(
            **{
                **args,
                "device_snapshot": replace(
                    args["device_snapshot"], execution_id=str(uuid4())
                ),
            },
            collect=lambda: pytest.fail("Recollected changed binding"),
        )


@pytest.mark.parametrize("kind", ("unknown_device", "missing_app", "wrong_count"))
def test_invalid_links_record_failure_without_partial_software(
    inputs, monkeypatch, kind
):
    args, snapshot, links = inputs
    if kind == "unknown_device":
        links = json.dumps({"synthetic-app": [str(uuid4())]}).encode()
    elif kind == "missing_app":
        links = b"{}"
    else:
        links = b'{"synthetic-app":[]}'
    received = []
    monkeypatch.setattr(
        commands, "ingest_exposure", lambda *values: received.append(values)
    )
    collect_and_ingest_software(**args, collect=lambda: (snapshot, links))
    failure, pin, relations = received[0]
    assert failure.outcome == "failure" and failure.payload == b""
    assert pin == args["device_snapshot"].execution_id and relations is None
    collect_and_ingest_software(
        **args, collect=lambda: pytest.fail("Retried failed collection")
    )
    assert received[1] == received[0]


def test_empty_software_is_complete_with_explicit_empty_links(inputs, monkeypatch):
    args, snapshot, _ = inputs
    snapshot = replace(snapshot, payload=b"[]")
    monkeypatch.setattr(commands, "ingest_exposure", lambda *values: values)
    assert collect_and_ingest_software(**args, collect=lambda: (snapshot, b"{}")) == (
        snapshot,
        args["device_snapshot"].execution_id,
        b"{}",
    )


def http_collect(inputs, handler, *, edge_route=None):
    import httpx
    from microsoft_evidence.pipeline import connection_scope
    from microsoft_evidence.software_pipeline import collect_software
    from microsoft_evidence.transport import MicrosoftHttpTransport
    from tests.test_microsoft_live_authority import _live_prepared
    from tests.test_microsoft_transport import _lease

    args, _, _ = inputs

    def authority(path):
        prepared = _live_prepared(
            scope=connection_scope(args["scope"]),
            source_input=(
                "intune",
                path,
                "https://graph.microsoft.com",
                ("DeviceManagementManagedDevices.Read.All",),
            ),
        )
        return prepared, _lease(prepared)

    prepared, token = authority("/v1.0/deviceManagement/detectedApps")
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        return collect_software(
            **{key: value for key, value in args.items() if key != "root"},
            prepared=prepared,
            token=token,
            transport=MicrosoftHttpTransport(client=client, now=lambda: NOW),
            application_device_authority=lambda app: authority(
                edge_route
                or f"/v1.0/deviceManagement/detectedApps/{app}/managedDevices"
            ),
        )


def test_http_software_collects_paginated_associations(inputs):
    import httpx

    args, app_snapshot, links = inputs
    paths = []

    def handler(request):
        paths.append(str(request.url))
        if request.url.path.endswith("/detectedApps"):
            return httpx.Response(200, json={"value": app_snapshot.records()})
        if "$skiptoken" not in request.url.params:
            return httpx.Response(
                200,
                json={
                    "value": [],
                    "@odata.nextLink": f"https://graph.microsoft.com{request.url.path}?$select=id&$skiptoken=next",
                },
            )
        return httpx.Response(200, json={"value": args["device_snapshot"].records()})

    snapshot, collected_links = http_collect(inputs, handler)
    assert snapshot.records() == app_snapshot.records()
    assert json.loads(collected_links) == json.loads(links)
    assert len(paths) == 3


def test_http_empty_software_does_not_request_associations(inputs):
    import httpx

    paths = []

    def handler(request):
        paths.append(request.url.path)
        return httpx.Response(200, json={"value": []})

    snapshot, links = http_collect(inputs, handler)
    assert snapshot.records() == [] and links == b"{}"
    assert paths == ["/v1.0/deviceManagement/detectedApps"]


@pytest.mark.parametrize(
    "kind", ("duplicate", "unsafe_id", "dot", "dotdot", "wrong_route", "unknown_device")
)
def test_http_software_rejects_invalid_association_collection(inputs, kind):
    import httpx

    _, snapshot, _ = inputs
    apps = list(snapshot.records())
    if kind == "duplicate":
        apps *= 2
    if kind == "unsafe_id":
        apps[0]["id"] = "../managedDevices"
    elif kind in ("dot", "dotdot"):
        apps[0]["id"] = "." if kind == "dot" else ".."

    def handler(request):
        if request.url.path.endswith("/detectedApps"):
            return httpx.Response(200, json={"value": apps})
        return httpx.Response(200, json={"value": [{"id": str(uuid4())}]})

    with pytest.raises(ValueError):
        http_collect(
            inputs,
            handler,
            edge_route="/v1.0/devices" if kind == "wrong_route" else None,
        )


def test_http_software_enforces_aggregate_record_bound(inputs, monkeypatch):
    import httpx
    from microsoft_evidence import software_pipeline

    args, snapshot, _ = inputs
    monkeypatch.setattr(software_pipeline, "MAX_RECORDS", 1)

    def handler(request):
        records = (
            snapshot.records()
            if request.url.path.endswith("/detectedApps")
            else args["device_snapshot"].records()
        )
        return httpx.Response(200, json={"value": records})

    with pytest.raises(ValueError, match="aggregate bounds"):
        http_collect(inputs, handler)


@pytest.mark.parametrize(
    "case", ["matching", "empty", "duplicate", "wrong_binding", "escaped_continuation"]
)
def test_device_software_relationship_preserves_exact_association(inputs, case):
    import httpx
    from microsoft_evidence.software_pipeline import (
        collect_software,
        device_software_path,
    )
    from microsoft_evidence.pipeline import connection_scope
    from microsoft_evidence.transport import (
        MicrosoftHttpTransport,
        MicrosoftTransportError,
    )
    from tests.test_microsoft_live_authority import _live_prepared
    from tests.test_microsoft_transport import _lease

    args, app, _ = inputs
    native = args["device_snapshot"].records()[0]["id"]
    scope = replace(args["scope"], scope_reference="managed-device-apps:" + native)
    device = args["device_snapshot"]
    if case == "wrong_binding":
        device = replace(device, payload=json.dumps([{"id": str(uuid4())}]).encode())
    route = device_software_path(native)
    prepared = _live_prepared(
        scope=connection_scope(scope),
        source_input=(
            "intune",
            route,
            "https://graph.microsoft.com",
            ("DeviceManagementManagedDevices.Read.All",),
        ),
    )
    calls = []

    def handler(request):
        calls.append(request)
        assert request.url.path == route
        records = [] if case == "empty" else app.records()
        if case == "duplicate":
            records *= 2
        body = {"value": records}
        if case == "escaped_continuation":
            body["@odata.nextLink"] = (
                "https://graph.microsoft.com/beta/deviceManagement/detectedApps?$skiptoken=next"
            )
        return httpx.Response(200, json=body)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:

        def collect():
            return collect_software(
                scope=scope,
                execution_id=str(uuid4()),
                device_snapshot=device,
                prepared=prepared,
                token=_lease(prepared),
                transport=MicrosoftHttpTransport(client=client, now=lambda: NOW),
                application_device_authority=lambda _: pytest.fail(
                    "Scoped software must not enumerate other devices"
                ),
                now=lambda: NOW,
            )

        if case in ("matching", "empty"):
            snapshot, links = collect()
            assert json.loads(links) == (
                {} if case == "empty" else {"synthetic-app": [native]}
            )
            assert len(snapshot.records()) == (case == "matching")
        else:
            with pytest.raises((ValueError, MicrosoftTransportError)):
                collect()
    assert len(calls) == (0 if case == "wrong_binding" else 1)
