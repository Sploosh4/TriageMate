"""Signed synthetic authority, paginated wire responses and offline health replay."""

from dataclasses import replace
import json
from uuid import uuid4

import httpx
import pytest

from microsoft_evidence import collector_command as command
from microsoft_evidence.antivirus_pipeline import collect_antivirus, INPUT_ID, PATH
from microsoft_evidence.pipeline import connection_scope, device_binding
from microsoft_evidence.transport import MicrosoftHttpTransport, MicrosoftTransportError
from standalone.evidence_pipeline.parsing.antivirus import normalize_antivirus
from standalone.evidence_pipeline.contracts import Snapshot
from standalone.evidence_pipeline.collection.snapshot_bundle import prepare
from tests.test_microsoft_pipeline import scope
from tests.test_microsoft_collector_command import config_file  # noqa: F401
from tests.test_microsoft_live_authority import NOW, _live_prepared
from tests.test_microsoft_transport import _lease


@pytest.fixture
def inputs():
    source = replace(scope(), source="Defender")
    device = Snapshot(
        source, str(uuid4()), NOW, NOW, "success", True, b'[{"id":"synthetic-device"}]'
    )
    source = replace(source, connection_id=str(uuid4()), input_kind="antivirus")
    prepared = _live_prepared(
        scope=connection_scope(source),
        source_input=(
            "defender",
            PATH,
            "https://api.security.microsoft.com",
            ("Machine.Read.All",),
        ),
    )
    prepared = prepared.model_copy(
        update={
            "endpoint": prepared.endpoint.model_copy(
                update={
                    "allowed_query_parameter_names": (),
                    "paging_query_parameter_names": ("$skip",),
                }
            )
        }
    )
    record = {
        "id": "synthetic-health",
        "machineId": "synthetic-device",
        "avMode": "0",
        "avIsSignatureUpToDate": "Unknown",
        "avIsEngineUpToDate": "False",
    }
    return source, device, prepared, record


def collect(inputs, handler, **transport_options):
    source, device, prepared, _ = inputs
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        return collect_antivirus(
            scope=source,
            execution_id=str(uuid4()),
            device_snapshot=device,
            prepared=prepared,
            token=_lease(prepared),
            transport=MicrosoftHttpTransport(
                client=client, now=lambda: NOW, **transport_options
            ),
            now=lambda: NOW,
        )


def test_pages_preserve_source_records_and_strip_unretained_fields(inputs):
    requests = []

    def handler(request):
        requests.append(request)
        if len(requests) == 1:
            assert not request.url.query
            return httpx.Response(
                200,
                json={
                    "value": [{**inputs[3], "cloudProtectionState": "not-retained"}],
                    "@odata.nextLink": "https://api.security.microsoft.com/api/deviceavinfo?$skip=1",
                },
            )
        return httpx.Response(
            200, json={"value": [{**inputs[3], "id": "synthetic-health-2"}]}
        )

    snapshot = collect(inputs, handler)
    records = normalize_antivirus(snapshot, {"synthetic-device"})
    assert len(records) == len(requests) == 2
    assert b"cloudProtectionState" not in snapshot.payload
    assert records[0].observation()["signature_current"] is None
    assert records[0].observation()["signature_status"] == "Unknown"
    assert records[0].observation()["engine_current"] is False


@pytest.mark.parametrize("field", ["id", "machineId"])
def test_required_fields_cannot_be_lost_during_projection(inputs, field):
    record = dict(inputs[3])
    del record[field]
    with pytest.raises(MicrosoftTransportError, match="schema"):
        collect(inputs, lambda _: httpx.Response(200, json={"value": [record]}))


@pytest.mark.parametrize("change", ["device", "duplicate", "boolean"])
def test_invalid_source_records_reject_whole_snapshot(inputs, change):
    record = dict(inputs[3])
    records = [record]
    if change == "device":
        record["machineId"] = "unknown-device"
    elif change == "duplicate":
        records.append(record)
    else:
        record["avIsSignatureUpToDate"] = True
    with pytest.raises(ValueError):
        collect(inputs, lambda _: httpx.Response(200, json={"value": records}))


@pytest.mark.parametrize(
    "change", ["tenant", "origin", "incomplete", "route", "authority"]
)
def test_authority_and_device_context_checked_before_http(inputs, change):
    source, device, prepared, record = inputs
    if change == "tenant":
        device = replace(device, scope=replace(device.scope, tenant_id=str(uuid4())))
    elif change == "origin":
        device = replace(device, scope=replace(device.scope, origin="synthetic"))
    elif change == "incomplete":
        device = replace(device, complete=False, outcome="failure", payload=b"")
    elif change == "route":
        prepared = prepared.model_copy(
            update={
                "endpoint": prepared.endpoint.model_copy(
                    update={"path_template": "/api/machines"}
                )
            }
        )
    else:
        source = replace(source, connection_id=str(uuid4()))
    with pytest.raises(ValueError):
        collect(
            (source, device, prepared, record),
            lambda _: pytest.fail("HTTP before valid binding"),
        )


def test_empty_health_snapshot_is_complete(inputs):
    assert (
        collect(inputs, lambda _: httpx.Response(200, json={"value": []})).records()
        == []
    )


def test_failure_after_first_page_never_publishes_partial_snapshot(inputs):
    calls = []

    def handler(request):
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(
                200,
                json={
                    "value": [inputs[3]],
                    "@odata.nextLink": "https://api.security.microsoft.com/api/deviceavinfo?$skip=1",
                },
            )
        return httpx.Response(403)

    with pytest.raises(MicrosoftTransportError):
        collect(inputs, handler)
    assert len(calls) == 2


@pytest.mark.parametrize("network", [False, True])
def test_command_replay_uses_saved_device_binding_without_credentials(
    inputs, tmp_path, monkeypatch, network
):
    from types import SimpleNamespace

    source, device, _, record = inputs
    root = tmp_path / "bundles"
    root.mkdir(mode=0o700)
    config = SimpleNamespace(scope=source, bundle_root=root)
    snapshot = Snapshot(
        source, str(uuid4()), NOW, NOW, "success", True, json.dumps([record]).encode()
    )
    prepare(
        source,
        snapshot.execution_id,
        root,
        collect=lambda: snapshot,
        binding=device_binding(source, device, source="Defender"),
    )
    monkeypatch.setattr(
        command.httpx,
        "Client",
        lambda **_: pytest.fail("HTTP client created during replay"),
    )
    calls = []
    monkeypatch.setattr(
        command,
        "ingest_exposure",
        lambda s, d: calls.append((s, d)) or {"outcome": "success"},
    )
    assert (
        command.run(
            config, snapshot.execution_id, device_snapshot=device, allow_network=network
        )["outcome"]
        == "success"
    )
    assert calls == [(snapshot, device.execution_id)]
    with pytest.raises(ValueError, match="binding differs"):
        command.run(
            config,
            snapshot.execution_id,
            device_snapshot=replace(device, execution_id=str(uuid4())),
            allow_network=network,
        )
    assert len(calls) == 1


@pytest.fixture
def antivirus_config(config_file):  # noqa: F811
    from dataclasses import asdict
    from microsoft_evidence import cloud
    from standalone.evidence_pipeline.contracts import SourceScope

    path, body = config_file
    source = replace(
        SourceScope(**body["scope"]), source="Defender", input_kind="antivirus"
    )
    body["scope"] = asdict(source)
    endpoint = body["endpoint"]
    endpoint.update(
        product="defender",
        host="api.security.microsoft.com",
        path_template=PATH,
        token_audience="https://api.securitycenter.microsoft.com",
        allowed_query_parameter_names=[],
        continuation_query_parameter_names=["$skip"],
    )
    endpoint["endpoint_policy_sha256"] = cloud._canonical_sha256(
        {k: v for k, v in endpoint.items() if k != "endpoint_policy_sha256"}
    )
    body["manifest"] = cloud._build_synthetic_manifest(
        classification="live",
        scope=connection_scope(source),
        audience=endpoint["token_audience"],
        grants=(cloud.PermissionGrant(role="Machine.Read.All", effect="read"),),
    ).model_dump(mode="json")
    path.write_text(json.dumps(body))
    return path, body


def test_antivirus_configuration_pins_route_scope_and_permission(antivirus_config):
    path, _ = antivirus_config
    config = command.load_configuration(path)
    prepared = config.prepared(NOW)
    assert prepared.scope.input_kind == "antivirus"
    assert prepared.expected_roles == ("Machine.Read.All",)
    assert prepared.endpoint.path_template == PATH
    assert (
        MicrosoftHttpTransport._source_contract(
            prepared, source_input_id=INPUT_ID
        ).input_id
        == INPUT_ID
    )


def test_live_command_retry_after_uncertain_import_does_not_recollect(
    antivirus_config, monkeypatch
):
    path, _ = antivirus_config
    config = command.load_configuration(path)
    device = Snapshot(
        replace(config.scope, connection_id=str(uuid4()), input_kind="devices"),
        str(uuid4()),
        NOW,
        NOW,
        "success",
        True,
        b'[{"id":"synthetic-device"}]',
    )
    requests, imports = [], []

    def handler(request):
        requests.append(request)
        return httpx.Response(
            200,
            json={
                "value": [{"id": "synthetic-health", "machineId": "synthetic-device"}]
            },
        )

    original_client = httpx.Client
    monkeypatch.setattr(
        command.httpx,
        "Client",
        lambda **kwargs: original_client(
            transport=httpx.MockTransport(handler), **kwargs
        ),
    )
    monkeypatch.setattr(command, "LocalCertificateResolver", lambda **kwargs: object())
    monkeypatch.setattr(
        command, "acquire_resource_token", lambda **kwargs: _lease(kwargs["prepared"])
    )

    def ingest(snapshot, device_attempt):
        imports.append((snapshot, device_attempt))
        if len(imports) == 1:
            raise RuntimeError("Synthetic lost commit acknowledgement")
        return {"outcome": "success"}

    monkeypatch.setattr(command, "ingest_exposure", ingest)
    execution = str(uuid4())
    with pytest.raises(RuntimeError, match="acknowledgement"):
        command.run(
            config,
            execution,
            device_snapshot=device,
            allow_network=True,
            now=lambda: NOW,
        )
    assert (
        command.run(
            config,
            execution,
            device_snapshot=device,
            allow_network=False,
            now=lambda: NOW,
        )["outcome"]
        == "success"
    )
    assert imports[0] == imports[1]
    assert imports[0][0].complete
    assert len(requests) == 1


@pytest.mark.parametrize(
    "case",
    [
        "matching",
        "empty",
        "wrong_device",
        "continuation",
        "wrong_binding",
        "invalid_selector",
        "full_page",
    ],
)
def test_device_scoped_health_cannot_expand_collection(inputs, case):
    source, device, _, record = inputs
    native = "a" * 40
    source = replace(
        source,
        scope_reference="native-device-id:"
        + ("bad" if case == "invalid_selector" else native),
    )
    device = replace(
        device,
        payload=json.dumps(
            [{"id": "b" * 40 if case == "wrong_binding" else native}]
        ).encode(),
    )
    prepared = _live_prepared(
        scope=connection_scope(source),
        source_input=(
            "defender",
            PATH,
            "https://api.security.microsoft.com",
            ("Machine.Read.All",),
        ),
    )
    prepared = prepared.model_copy(
        update={
            "endpoint": prepared.endpoint.model_copy(
                update={"allowed_query_parameter_names": ("$filter", "$top")}
            )
        }
    )
    calls = []

    def handler(request):
        calls.append(request)
        assert request.url.params["$filter"] == f"machineId eq '{native}'"
        assert request.url.params["$top"] == "10000"
        selected = {
            **record,
            "machineId": "b" * 40 if case == "wrong_device" else native,
        }
        body = {"value": [] if case == "empty" else [selected]}
        if case == "full_page":
            body["value"] = [{**selected, "id": str(i)} for i in range(10000)]
        if case == "continuation":
            body["@odata.nextLink"] = (
                "https://api.security.microsoft.com/api/deviceavinfo?$skip=1"
            )
        return httpx.Response(200, json=body)

    args = (source, device, prepared, record)
    if case in ("matching", "empty"):
        assert len(collect(args, handler).records()) == (case == "matching")
    else:
        with pytest.raises((ValueError, MicrosoftTransportError)):
            collect(args, handler)
    assert len(calls) == (0 if case in ("wrong_binding", "invalid_selector") else 1)
