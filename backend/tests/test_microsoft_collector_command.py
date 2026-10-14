"""Command configuration and offline replay; generated local fixtures only."""

from dataclasses import asdict
import json
from uuid import uuid4
import pytest

from microsoft_evidence import cloud, collector_command as command
from microsoft_evidence.pipeline import connection_scope
from standalone.evidence_pipeline.contracts import Snapshot
from standalone.evidence_pipeline.collection.snapshot_bundle import prepare
from tests.test_microsoft_pipeline import scope
from tests.test_microsoft_live_authority import NOW


@pytest.fixture
def config_file(tmp_path):
    source = scope()
    endpoint_values = next(iter(cloud._ENDPOINT_POLICIES.values())).model_dump(
        mode="json", exclude={"endpoint_policy_sha256"}
    )
    endpoint_values["classification"] = "live"
    endpoint = cloud.MicrosoftEndpointPolicy(
        **endpoint_values,
        endpoint_policy_sha256=cloud._canonical_sha256(endpoint_values),
    )
    manifest = cloud._build_synthetic_manifest(
        classification="live", scope=connection_scope(source)
    )
    root = tmp_path / "bundles"
    root.mkdir(mode=0o700)
    body = dict(
        scope=asdict(source),
        endpoint=endpoint.model_dump(mode="json"),
        manifest=manifest.model_dump(mode="json"),
        key_path=str(tmp_path / "unused-key.pem"),
        certificate_path=str(tmp_path / "unused-cert.pem"),
        bundle_root=str(root),
    )
    path = tmp_path / "config.json"
    path.write_text(json.dumps(body))
    path.chmod(0o600)
    return path, body


def test_valid_configuration_prepares_exact_connection(config_file):
    path, _ = config_file
    config = command.load_configuration(path)
    assert config.prepared(NOW).scope == connection_scope(config.scope)


@pytest.mark.parametrize("source", ("Entra", "Intune", "Defender"))
@pytest.mark.parametrize(
    "audience",
    (
        "https://graph.microsoft.com",
        "https://api.security.microsoft.com",
        "https://api.securitycenter.microsoft.com",
        "https://api.securitycenter.microsoft.com.evil.example",
    ),
)
def test_resource_audience_is_closed_and_product_specific(
    config_file, source, audience
):
    from standalone.evidence_pipeline.contracts import SourceScope
    from microsoft_evidence.source_registry import SOURCE_INPUTS

    path, body = config_file
    body["scope"]["source"] = source
    product, input_id, route = command.DEVICE_INPUTS[source]
    endpoint = body["endpoint"]
    host = (
        "api.security.microsoft.com" if source == "Defender" else "graph.microsoft.com"
    )
    endpoint.update(
        product=product, host=host, path_template=route, token_audience=audience
    )
    endpoint["endpoint_policy_sha256"] = cloud._canonical_sha256(
        {k: v for k, v in endpoint.items() if k != "endpoint_policy_sha256"}
    )
    permissions = next(
        x.application_permissions for x in SOURCE_INPUTS if x.input_id == input_id
    )
    manifest = cloud._build_synthetic_manifest(
        classification="live",
        scope=connection_scope(SourceScope(**body["scope"])),
        audience=audience,
        grants=tuple(
            cloud.PermissionGrant(role=role, effect="read") for role in permissions
        ),
    )
    body["manifest"] = manifest.model_dump(mode="json")
    path.write_text(json.dumps(body))
    accepted = audience in (
        {
            "https://api.security.microsoft.com",
            "https://api.securitycenter.microsoft.com",
        }
        if source == "Defender"
        else {"https://graph.microsoft.com"}
    )
    if accepted:
        prepared = command.load_configuration(path).prepared(NOW)
        assert prepared.audience == audience
    else:
        with pytest.raises(ValueError, match="fixed collection policy"):
            command.load_configuration(path)


@pytest.mark.parametrize("change", ("extra", "permissions", "relative", "host"))
def test_invalid_configuration_rejected(config_file, change):
    path, body = config_file
    if change == "extra":
        body["password"] = "synthetic-not-allowed"
    elif change == "permissions":
        path.chmod(0o644)
    elif change == "relative":
        body["key_path"] = "relative.pem"
    else:
        endpoint = body["endpoint"]
        endpoint["host"] = "elsewhere.example"
        endpoint["endpoint_policy_sha256"] = cloud._canonical_sha256(
            {
                key: value
                for key, value in endpoint.items()
                if key != "endpoint_policy_sha256"
            }
        )
    path.write_text(json.dumps(body))
    with pytest.raises(ValueError):
        command.load_configuration(path)


@pytest.mark.parametrize("network", (False, True))
def test_existing_bundle_replays_without_credentials_or_http(
    config_file, monkeypatch, network
):
    path, _ = config_file
    config = command.load_configuration(path)
    execution = str(uuid4())
    snapshot = Snapshot(config.scope, execution, NOW, NOW, "success", True, b"[]")
    prepare(config.scope, execution, config.bundle_root, collect=lambda: snapshot)
    monkeypatch.setattr(
        command.httpx,
        "Client",
        lambda **kwargs: pytest.fail("Created HTTP client during replay"),
    )
    received = []
    monkeypatch.setattr(
        command,
        "ingest",
        lambda snapshot: received.append(snapshot) or {"outcome": "success"},
    )
    assert command.run(config, execution, allow_network=network) == {
        "outcome": "success"
    }
    assert received == [snapshot]


def test_disabled_network_does_not_create_new_bundle(config_file):
    path, _ = config_file
    config = command.load_configuration(path)
    execution = str(uuid4())
    with pytest.raises(ValueError, match="allow-network"):
        command.run(config, execution)
    assert not (config.bundle_root / execution).exists()


def test_acquisition_failure_saved_and_replayed(config_file, monkeypatch):
    path, _ = config_file
    config = command.load_configuration(path)
    execution = str(uuid4())
    calls = []

    def fail(**kwargs):
        calls.append(1)
        raise command.MicrosoftLiveAuthorityError("synthetic-error")

    monkeypatch.setattr(command, "acquire_resource_token", fail)
    monkeypatch.setattr(
        command,
        "ingest",
        lambda snapshot: {"outcome": snapshot.outcome, "error": snapshot.error_code},
    )
    first = command.run(config, execution, allow_network=True, now=lambda: NOW)
    assert first == {"outcome": "failure", "error": "microsoft_collection_failed"}
    assert command.run(config, execution, now=lambda: NOW) == first
    assert calls == [1]


def test_new_collection_acquires_then_collects_and_ingests(config_file, monkeypatch):
    import httpx
    from microsoft_evidence.live_authority import MicrosoftCredentialMaterial

    path, _ = config_file
    config = command.load_configuration(path)
    execution = str(uuid4())
    calls = []
    received = []
    original_client = httpx.Client

    class Resolver:
        def resolve(self, reference):
            assert reference == config.manifest.credential_reference_id
            return MicrosoftCredentialMaterial(
                kind="client_assertion", value="synthetic-assertion"
            )

    def handler(request):
        calls.append(request.method)
        if request.method == "POST":
            return httpx.Response(
                200,
                json={
                    "access_token": "synthetic-opaque",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                },
            )
        assert request.headers["authorization"] == "Bearer synthetic-opaque"
        return httpx.Response(200, json={"value": []})

    def client(**kwargs):
        assert kwargs == {"trust_env": False, "follow_redirects": False}
        return original_client(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(
        command, "LocalCertificateResolver", lambda **kwargs: Resolver()
    )
    monkeypatch.setattr(command.httpx, "Client", client)
    monkeypatch.setattr(
        command,
        "ingest",
        lambda snapshot: received.append(snapshot) or {"outcome": snapshot.outcome},
    )
    assert command.run(config, execution, allow_network=True, now=lambda: NOW) == {
        "outcome": "success"
    }
    assert calls == ["POST", "GET"] and received[0].complete


@pytest.fixture
def finding_config(config_file):
    from dataclasses import replace
    from standalone.evidence_pipeline.contracts import SourceScope

    path, body = config_file
    source = replace(
        SourceScope(**body["scope"]), source="Defender", input_kind="findings"
    )
    body["scope"] = asdict(source)
    endpoint = body["endpoint"]
    endpoint.update(
        product="defender",
        host="api.security.microsoft.com",
        path_template="/api/vulnerabilities/machinesVulnerabilities",
        token_audience="https://api.security.microsoft.com",
        allowed_query_parameter_names=["$top"],
    )
    endpoint["endpoint_policy_sha256"] = cloud._canonical_sha256(
        {k: v for k, v in endpoint.items() if k != "endpoint_policy_sha256"}
    )
    manifest = cloud._build_synthetic_manifest(
        classification="live",
        scope=connection_scope(source),
        audience="https://api.security.microsoft.com",
        grants=(cloud.PermissionGrant(role="Vulnerability.Read.All", effect="read"),),
    )
    body["manifest"] = manifest.model_dump(mode="json")
    path.write_text(json.dumps(body))
    return command.load_configuration(path)


def test_finding_command_requires_device_binding_before_network(finding_config):
    with pytest.raises(ValueError, match="saved device execution"):
        command.run(finding_config, str(uuid4()), allow_network=True, now=lambda: NOW)


def test_finding_command_collects_then_replays_exact_binding(
    finding_config, monkeypatch
):
    from dataclasses import replace
    import httpx
    from tests.test_microsoft_transport import _lease

    cfg = finding_config
    device = Snapshot(
        replace(cfg.scope, input_kind="devices", connection_id=str(uuid4())),
        str(uuid4()),
        NOW,
        NOW,
        "success",
        True,
        b'[{"id":"synthetic-device"}]',
    )
    execution = str(uuid4())
    requests = []
    imports = []
    original = httpx.Client

    def handler(request):
        requests.append(request)
        assert request.url.path == "/api/vulnerabilities/machinesVulnerabilities"
        return httpx.Response(
            200,
            json={
                "value": [
                    {
                        "id": "synthetic-finding",
                        "machineId": "synthetic-device",
                        "cveId": "CVE-2026-999999",
                        "productName": "Synthetic product",
                    }
                ]
            },
        )

    monkeypatch.setattr(
        command.httpx,
        "Client",
        lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs),
    )
    monkeypatch.setattr(
        command, "acquire_resource_token", lambda **kwargs: _lease(kwargs["prepared"])
    )
    monkeypatch.setattr(
        command,
        "ingest_exposure",
        lambda snap, pin: imports.append((snap, pin)) or {"outcome": snap.outcome},
    )
    assert command.run(
        cfg, execution, allow_network=True, device_snapshot=device, now=lambda: NOW
    ) == {"outcome": "success"}
    assert command.run(cfg, execution, device_snapshot=device) == {"outcome": "success"}
    assert imports[0] == imports[1] and imports[0][1] == device.execution_id
    with pytest.raises(ValueError, match="binding differs"):
        command.run(
            cfg, execution, device_snapshot=replace(device, execution_id=str(uuid4()))
        )
    assert len(requests) == 1 and len(imports) == 2


def test_saved_device_loader_never_fetches(finding_config):
    from dataclasses import replace

    cfg = replace(
        finding_config, scope=replace(finding_config.scope, input_kind="devices")
    )
    execution = str(uuid4())
    with pytest.raises(ValueError, match="missing"):
        command.saved_device(cfg, execution)
    assert not (cfg.bundle_root / execution).exists()
    snapshot = Snapshot(cfg.scope, execution, NOW, NOW, "success", True, b"[]")
    prepare(cfg.scope, execution, cfg.bundle_root, collect=lambda: snapshot)
    assert command.saved_device(cfg, execution) == snapshot


@pytest.mark.parametrize("argument", ("--device-config", "--device-execution-id"))
def test_cli_rejects_incomplete_device_arguments(monkeypatch, argument):
    monkeypatch.setattr(
        command, "load_configuration", lambda path: pytest.fail("Read configuration")
    )
    with pytest.raises(SystemExit) as error:
        command.main(
            ["--config", "unused", "--execution-id", str(uuid4()), argument, "unused"]
        )
    assert error.value.code == 2


def test_device_command_rejects_binding(config_file):
    path, _ = config_file
    config = command.load_configuration(path)
    device = Snapshot(config.scope, str(uuid4()), NOW, NOW, "success", True, b"[]")
    with pytest.raises(ValueError, match="does not accept"):
        command.run(config, str(uuid4()), allow_network=True, device_snapshot=device)


@pytest.fixture
def software_configs(config_file):
    from dataclasses import replace
    from standalone.evidence_pipeline.contracts import SourceScope

    path, body = config_file
    source = replace(
        SourceScope(**body["scope"]), source="Intune", input_kind="software"
    )
    body["scope"] = asdict(source)
    body["manifest"] = cloud._build_synthetic_manifest(
        classification="live",
        scope=connection_scope(source),
        grants=(
            cloud.PermissionGrant(
                role="DeviceManagementManagedDevices.Read.All", effect="read"
            ),
        ),
    ).model_dump(mode="json")
    configs = []
    for route in (command.APP_PATH, command.EDGE_PATH):
        endpoint = body["endpoint"]
        endpoint.update(product="intune", path_template=route)
        endpoint["endpoint_policy_sha256"] = cloud._canonical_sha256(
            {
                key: value
                for key, value in endpoint.items()
                if key != "endpoint_policy_sha256"
            }
        )
        path.write_text(json.dumps(body))
        configs.append(command.load_configuration(path))
    device_id = str(uuid4())
    device = Snapshot(
        replace(source, connection_id=str(uuid4()), input_kind="devices"),
        str(uuid4()),
        NOW,
        NOW,
        "success",
        True,
        json.dumps([{"id": device_id}]).encode(),
    )
    return *configs, device


def test_software_command_collects_bound_routes_and_replays(
    software_configs, monkeypatch
):
    import httpx
    from standalone.evidence_pipeline import commands
    from tests.test_microsoft_transport import _lease

    config, edge_config, device = software_configs
    requests, imported = [], []
    original = httpx.Client

    def handler(request):
        requests.append(request.url.path)
        records = (
            [{"id": "synthetic-app", "displayName": "Synthetic app", "deviceCount": 1}]
            if request.url.path == command.APP_PATH
            else device.records()
        )
        return httpx.Response(200, json={"value": records})

    monkeypatch.setattr(
        command.httpx,
        "Client",
        lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs),
    )
    monkeypatch.setattr(
        command, "acquire_resource_token", lambda **kwargs: _lease(kwargs["prepared"])
    )
    monkeypatch.setattr(
        commands,
        "ingest_exposure",
        lambda *values: imported.append(values) or {"outcome": "success"},
    )
    execution = str(uuid4())
    args = dict(device_snapshot=device, association_config=edge_config, now=lambda: NOW)
    assert command.run(config, execution, allow_network=True, **args) == {
        "outcome": "success"
    }
    assert command.run(config, execution, **args) == {"outcome": "success"}
    assert requests == [
        command.APP_PATH,
        command.APP_PATH + "/synthetic-app/managedDevices",
    ]
    assert imported[0] == imported[1]
    assert json.loads(imported[0][2]) == {"synthetic-app": [device.records()[0]["id"]]}


@pytest.mark.parametrize("kind", ("missing", "wrong_scope", "wrong_route", "offline"))
def test_software_command_rejects_configuration_before_http(
    software_configs, monkeypatch, kind
):
    from dataclasses import replace

    config, edge, device = software_configs
    if kind == "missing":
        edge = None
    elif kind == "wrong_scope":
        edge = replace(edge, scope=replace(edge.scope, connection_id=str(uuid4())))
    elif kind == "wrong_route":
        edge = config
    monkeypatch.setattr(
        command.httpx, "Client", lambda **kwargs: pytest.fail("Created HTTP client")
    )
    with pytest.raises(ValueError):
        command.run(
            config,
            str(uuid4()),
            allow_network=kind != "offline",
            device_snapshot=device,
            association_config=edge,
            now=lambda: NOW,
        )


@pytest.fixture
def missing_patch_config(config_file):
    from dataclasses import replace

    path, body = config_file
    source = replace(scope(), source="Defender", input_kind="missing_patches")
    endpoint = body["endpoint"]
    endpoint.update(
        product="defender",
        host="api.security.microsoft.com",
        path_template=command.MISSING_PATCH_PATH,
        token_audience="https://api.security.microsoft.com",
    )
    endpoint["endpoint_policy_sha256"] = cloud._canonical_sha256(
        {k: v for k, v in endpoint.items() if k != "endpoint_policy_sha256"}
    )
    manifest = cloud._build_synthetic_manifest(
        classification="live",
        scope=connection_scope(source),
        audience="https://api.security.microsoft.com",
        grants=tuple(
            cloud.PermissionGrant(role=r, effect="read")
            for r in ("Software.Read.All", "Vulnerability.Read.All")
        ),
    )
    body.update(scope=asdict(source), manifest=manifest.model_dump(mode="json"))
    path.write_text(json.dumps(body))
    config = command.load_configuration(path)
    device_scope = replace(source, connection_id=str(uuid4()), input_kind="devices")
    device = Snapshot(
        device_scope,
        str(uuid4()),
        NOW,
        NOW,
        "success",
        True,
        b'[{"id":"synthetic-device"}]',
    )
    return config, device


def test_missing_patch_requires_saved_devices_and_network_flag(missing_patch_config):
    config, device = missing_patch_config
    execution = str(uuid4())
    with pytest.raises(ValueError, match="saved device"):
        command.run(config, execution)
    with pytest.raises(ValueError, match="allow-network"):
        command.run(config, execution, device_snapshot=device)
    assert not (config.bundle_root / execution).exists()


def test_missing_patch_command_real_http_and_offline_replay(
    missing_patch_config, monkeypatch
):
    import httpx
    from microsoft_evidence.live_authority import MicrosoftCredentialMaterial

    config, device = missing_patch_config
    execution = str(uuid4())
    original_client = httpx.Client
    requests = []
    received = []

    class Resolver:
        def resolve(self, reference):
            return MicrosoftCredentialMaterial(
                kind="client_assertion", value="synthetic-assertion"
            )

    def handler(request):
        requests.append(request)
        if request.method == "POST":
            return httpx.Response(
                200,
                json={
                    "access_token": "synthetic-opaque",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                },
            )
        assert request.url.path == "/api/machines/synthetic-device/getmissingkbs"
        return httpx.Response(200, json={"value": [{"id": "KB-SYNTHETIC"}]})

    monkeypatch.setattr(
        command, "LocalCertificateResolver", lambda **kwargs: Resolver()
    )
    monkeypatch.setattr(
        command.httpx,
        "Client",
        lambda **kwargs: original_client(
            transport=httpx.MockTransport(handler), **kwargs
        ),
    )
    monkeypatch.setattr(
        command,
        "ingest_exposure",
        lambda snapshot, device_id: (
            received.append((snapshot, device_id)) or {"outcome": snapshot.outcome}
        ),
    )
    assert command.run(
        config, execution, device_snapshot=device, allow_network=True, now=lambda: NOW
    ) == {"outcome": "success"}
    assert [r.method for r in requests] == ["POST", "GET"]
    assert received[0][0].records() == [
        {"id": "KB-SYNTHETIC", "machineId": "synthetic-device"}
    ]
    assert received[0][1] == device.execution_id
    monkeypatch.setattr(
        command.httpx, "Client", lambda **kwargs: pytest.fail("Network on replay")
    )
    assert command.run(config, execution, device_snapshot=device, now=lambda: NOW) == {
        "outcome": "success"
    }


def test_missing_patch_command_preserves_failure_and_rejects_changed_binding(
    missing_patch_config, monkeypatch
):
    from dataclasses import replace

    config, device = missing_patch_config
    execution = str(uuid4())
    calls = []

    def failure(*args):
        calls.append(1)
        raise command.MicrosoftTransportError("synthetic provider detail")

    monkeypatch.setattr(command, "fetch_missing_patches", failure)
    monkeypatch.setattr(
        command,
        "ingest_exposure",
        lambda snapshot, device_id: {
            "outcome": snapshot.outcome,
            "error": snapshot.error_code,
        },
    )
    expected = {"outcome": "failure", "error": "microsoft_collection_failed"}
    assert (
        command.run(
            config,
            execution,
            device_snapshot=device,
            allow_network=True,
            now=lambda: NOW,
        )
        == expected
    )
    assert (
        command.run(config, execution, device_snapshot=device, now=lambda: NOW)
        == expected
    )
    assert calls == [1]
    with pytest.raises(ValueError, match="binding differs"):
        command.run(
            config,
            execution,
            device_snapshot=replace(device, execution_id=str(uuid4())),
        )


def test_missing_patch_wrong_tenant_rejected_before_network(
    missing_patch_config, monkeypatch
):
    from dataclasses import replace

    config, device = missing_patch_config
    monkeypatch.setattr(
        command.httpx, "Client", lambda **kwargs: pytest.fail("Network")
    )
    device = replace(device, scope=replace(device.scope, tenant_id=str(uuid4())))
    with pytest.raises(ValueError, match="same complete device scope"):
        command.run(config, str(uuid4()), device_snapshot=device, allow_network=True)


@pytest.mark.parametrize(
    "route",
    (
        "/api/recommendations",
        "/api/recommendations/{id}/machineReferences",
        "/api/machines/" + "a" * 40 + "/recommendations",
    ),
)
def test_recommendation_routes_require_their_exact_read_permission(config_file, route):
    from standalone.evidence_pipeline.contracts import SourceScope

    path, body = config_file
    body["scope"].update(source="Defender", input_kind="recommendations")
    if route.startswith("/api/machines/"):
        body["scope"]["scope_reference"] = "native-device-id:" + "a" * 40
    body["endpoint"].update(
        product="defender",
        host="api.security.microsoft.com",
        path_template=route,
        token_audience="https://api.security.microsoft.com",
    )
    body["endpoint"]["endpoint_policy_sha256"] = cloud._canonical_sha256(
        {k: v for k, v in body["endpoint"].items() if k != "endpoint_policy_sha256"}
    )

    def write_manifest(role):
        body["manifest"] = cloud._build_synthetic_manifest(
            classification="live",
            scope=connection_scope(SourceScope(**body["scope"])),
            audience="https://api.security.microsoft.com",
            grants=(cloud.PermissionGrant(role=role, effect="read"),),
        ).model_dump(mode="json")
        path.write_text(json.dumps(body))

    write_manifest("SecurityRecommendation.Read.All")
    assert command.load_configuration(path).endpoint.path_template == route
    write_manifest("Vulnerability.Read.All")
    with pytest.raises(ValueError):
        command.load_configuration(path)


def test_invalid_single_device_scope_is_rejected_on_configuration_load(config_file):
    path, body = config_file
    body["scope"]["scope_reference"] = "native-device-id:invalid"
    path.write_text(json.dumps(body))
    with pytest.raises(ValueError, match="single-device"):
        command.load_configuration(path)
