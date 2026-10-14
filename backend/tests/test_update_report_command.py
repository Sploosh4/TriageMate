"""Synthetic report-export command, including offline retries."""

from dataclasses import asdict, replace
from datetime import timedelta
import json
from uuid import uuid4

import httpx
import pytest

from microsoft_evidence import cloud, collector_command as command
from microsoft_evidence.live_authority import MicrosoftCredentialMaterial
from microsoft_evidence.pipeline import connection_scope
from microsoft_evidence.update_report_pipeline import POLICY_SCOPE_PREFIX
from standalone.evidence_pipeline.contracts import Snapshot
from tests.test_microsoft_collector_command import config_file  # noqa: F401
from tests.test_microsoft_pipeline import scope
from tests.test_microsoft_live_authority import NOW
from tests.test_intune_report_transport import (
    POLICY_ID,
    DEVICE_ID,
    _row,
    _zip_csv,
    _completed_handler,
)

GROUP_ID = "22222222-3333-4444-8555-666666666666"


@pytest.fixture
def report_config(config_file):  # noqa: F811
    path, body = config_file
    source = replace(
        scope(),
        source="Intune",
        input_kind="update_status",
        scope_reference=POLICY_SCOPE_PREFIX + POLICY_ID + ":group:" + GROUP_ID,
    )
    endpoint = body["endpoint"]
    endpoint.update(
        product="intune",
        path_template="/beta/deviceManagement/reports/exportJobs",
        api_versions=["beta"],
        allowed_query_parameter_names=[],
        continuation_query_parameter_names=[],
    )
    endpoint["endpoint_policy_sha256"] = cloud._canonical_sha256(
        {k: v for k, v in endpoint.items() if k != "endpoint_policy_sha256"}
    )
    manifest = cloud._build_synthetic_manifest(
        classification="live",
        scope=connection_scope(source),
        grants=(
            cloud.PermissionGrant(role="Device.Read.All", effect="read"),
            cloud.PermissionGrant(
                role="DeviceManagementConfiguration.ReadWrite.All", effect="read"
            ),
            cloud.PermissionGrant(role="GroupMember.Read.All", effect="read"),
        ),
        elevated_permission_approval_id="synthetic-explicit-report-approval",
        elevated_permission_approval_sha256="e" * 64,
    )
    body.update(scope=asdict(source), manifest=manifest.model_dump(mode="json"))
    path.write_text(json.dumps(body))
    config = command.load_configuration(path)
    device = Snapshot(
        replace(source, input_kind="devices", connection_id=str(uuid4())),
        str(uuid4()),
        NOW,
        NOW,
        "success",
        True,
        json.dumps([{"id": DEVICE_ID, "azureADDeviceId": DEVICE_ID}]).encode(),
    )
    return config, device


@pytest.mark.parametrize("failure", [None, "csv", "compression", "deflate"])
def test_report_command_exports_then_replays_without_credentials(
    report_config, monkeypatch, failure
):
    config, device = report_config
    execution = str(uuid4())
    original_client = httpx.Client
    import csv

    row = (
        _row(LatestAlertMessage="x" * (csv.field_size_limit() + 1))
        if failure == "csv"
        else _row()
    )
    archive = bytearray(_zip_csv([row]))
    if failure == "compression":
        central = archive.index(b"PK\x01\x02")
        archive[8:10] = (99).to_bytes(2, "little")
        archive[central + 10 : central + 12] = (99).to_bytes(2, "little")
    if failure == "deflate":
        offset = (
            30
            + int.from_bytes(archive[26:28], "little")
            + int.from_bytes(archive[28:30], "little")
        )
        archive[offset] = (archive[offset] & ~7) | 7
    respond = _completed_handler(bytes(archive))
    expected = {"outcome": "failure" if failure else "success"}
    requests = []
    imported = []

    class Resolver:
        def resolve(self, reference):
            return MicrosoftCredentialMaterial(
                kind="client_assertion", value="synthetic-assertion"
            )

    def handler(request):
        requests.append(request)
        if request.url.host == "login.microsoftonline.com":
            return httpx.Response(
                200,
                json={
                    "access_token": "synthetic-opaque",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                },
            )
        if request.url.path.endswith("/assignments"):
            assert request.headers["authorization"] == "Bearer synthetic-opaque"
            return httpx.Response(
                200,
                json={
                    "value": [
                        {
                            "target": {
                                "@odata.type": "#microsoft.graph.groupAssignmentTarget",
                                "groupId": GROUP_ID,
                            }
                        }
                    ]
                },
            )
        if request.url.path == "/v1.0/groups/" + GROUP_ID + "/members":
            assert request.headers["authorization"] == "Bearer synthetic-opaque"
            assert request.url.params["$top"] == "2"
            return httpx.Response(
                200,
                json={
                    "value": [
                        {
                            "@odata.type": "#microsoft.graph.device",
                            "id": str(uuid4()),
                            "deviceId": DEVICE_ID,
                        }
                    ]
                },
            )
        if request.method == "GET":
            assert "authorization" not in request.headers
        return respond(request)

    monkeypatch.setattr(command, "LocalCertificateResolver", lambda **kw: Resolver())
    monkeypatch.setattr(
        command.httpx,
        "Client",
        lambda **kw: original_client(transport=httpx.MockTransport(handler), **kw),
    )
    monkeypatch.setattr(
        command,
        "ingest_exposure",
        lambda snapshot, pin: (
            imported.append((snapshot, pin)) or {"outcome": snapshot.outcome}
        ),
    )
    args = dict(device_snapshot=device, now=lambda: NOW + timedelta(minutes=1))
    assert command.run(config, execution, allow_network=True, **args) == expected
    assert len(requests) == 5 and imported[0][1] == device.execution_id
    if failure:
        assert imported[0][0].payload == b""
        assert imported[0][0].error_code == "microsoft_collection_failed"
    else:
        assert "UPN" not in imported[0][0].records()[0]
        assert command.run(config, str(uuid4()), allow_network=True, **args) == expected
        assert len(requests) == 10  # Every fresh execution rechecks isolation.
    monkeypatch.setattr(
        command.httpx, "Client", lambda **kw: pytest.fail("Network on replay")
    )
    assert command.run(config, execution, **args) == expected
    with pytest.raises(ValueError, match="binding differs"):
        command.run(
            config,
            execution,
            device_snapshot=replace(device, execution_id=str(uuid4())),
        )


def test_report_requires_explicit_network_and_saved_devices(report_config):
    config, device = report_config
    execution = str(uuid4())
    with pytest.raises(ValueError, match="saved device"):
        command.run(config, execution, allow_network=True)
    with pytest.raises(ValueError, match="allow-network"):
        command.run(config, execution, device_snapshot=device)


def test_report_configuration_cannot_omit_elevated_approval(report_config, config_file):  # noqa: F811
    path, _ = config_file
    body = json.loads(path.read_text())
    manifest = body["manifest"]
    manifest["elevated_permission_approval_id"] = None
    manifest["elevated_permission_approval_sha256"] = None
    manifest["manifest_sha256"] = cloud._canonical_sha256(
        {k: v for k, v in manifest.items() if k != "manifest_sha256"}
    )
    path.write_text(json.dumps(body))
    with pytest.raises(ValueError, match="elevated permission approval"):
        command.load_configuration(path)


@pytest.mark.parametrize(
    "case",
    [
        "wrong_group",
        "extra_assignment",
        "assignment_page",
        "filter",
        "filter_type",
        "wrong_device",
        "extra_member",
        "member_page",
        "user_member",
        "empty_member",
        "assignment_denied",
        "member_denied",
        "malformed_json",
        "redirect",
    ],
)
def test_isolation_failure_never_requests_report_export(
    report_config, monkeypatch, case
):
    config, device = report_config
    requests = []
    imported = []
    original_client = httpx.Client

    class Resolver:
        def resolve(self, reference):
            return MicrosoftCredentialMaterial(
                kind="client_assertion", value="synthetic-assertion"
            )

    def handler(request):
        requests.append(request)
        if request.url.host == "login.microsoftonline.com":
            return httpx.Response(
                200,
                json={
                    "access_token": "synthetic-opaque",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                },
            )
        assert request.method == "GET", (
            "An isolation failure must prevent export creation"
        )
        assert request.url.host == "graph.microsoft.com"
        assignment = request.url.path.endswith("/assignments")
        assert assignment or request.url.path == "/v1.0/groups/" + GROUP_ID + "/members"
        if (assignment and case == "assignment_denied") or (
            not assignment and case == "member_denied"
        ):
            return httpx.Response(403)
        if assignment and case == "redirect":
            return httpx.Response(
                302, headers={"Location": "https://untrusted.example.invalid/"}
            )
        if assignment and case == "malformed_json":
            return httpx.Response(200, content=b"not json")
        target = {
            "@odata.type": "#microsoft.graph.groupAssignmentTarget",
            "groupId": GROUP_ID,
        }
        member = {"@odata.type": "#microsoft.graph.device", "deviceId": DEVICE_ID}
        if case == "wrong_group":
            target["groupId"] = str(uuid4())
        if case == "filter":
            target["deviceAndAppManagementAssignmentFilterId"] = str(uuid4())
        if case == "filter_type":
            target["deviceAndAppManagementAssignmentFilterType"] = "include"
        if case == "wrong_device":
            member["deviceId"] = str(uuid4())
        if case == "user_member":
            member["@odata.type"] = "#microsoft.graph.user"
        body = {"value": [{"target": target}] if assignment else [member]}
        if (assignment and case == "extra_assignment") or (
            not assignment and case == "extra_member"
        ):
            body["value"].append(body["value"][0])
        if not assignment and case == "empty_member":
            body["value"] = []
        if (assignment and case == "assignment_page") or (
            not assignment and case == "member_page"
        ):
            body["@odata.nextLink"] = "https://untrusted.example.invalid/"
        return httpx.Response(200, json=body)

    monkeypatch.setattr(command, "LocalCertificateResolver", lambda **kw: Resolver())
    monkeypatch.setattr(
        command.httpx,
        "Client",
        lambda **kw: original_client(transport=httpx.MockTransport(handler), **kw),
    )
    monkeypatch.setattr(
        command,
        "ingest_exposure",
        lambda snapshot, pin: (
            imported.append(snapshot) or {"outcome": snapshot.outcome}
        ),
    )
    execution = str(uuid4())
    args = dict(device_snapshot=device, now=lambda: NOW + timedelta(minutes=1))
    assert command.run(config, execution, allow_network=True, **args) == {
        "outcome": "failure"
    }
    assert len(requests) in (2, 3)
    assert imported[0].payload == b"" and not imported[0].complete
    monkeypatch.setattr(
        command.httpx, "Client", lambda **kw: pytest.fail("Network on failed replay")
    )
    assert command.run(config, execution, **args) == {"outcome": "failure"}


def test_legacy_policy_scope_replays_but_cannot_collect(
    report_config,
    config_file,  # noqa: F811
    monkeypatch,
):
    from microsoft_evidence.pipeline import device_binding
    from standalone.evidence_pipeline.collection.snapshot_bundle import prepare

    _, device = report_config
    path, _ = config_file
    body = json.loads(path.read_text())
    body["scope"]["scope_reference"] = POLICY_SCOPE_PREFIX + POLICY_ID
    manifest = body["manifest"]
    manifest["scope"]["scope_reference"] = body["scope"]["scope_reference"]
    manifest["grants"] = [
        g
        for g in manifest["grants"]
        if g["role"] == "DeviceManagementConfiguration.ReadWrite.All"
    ]
    manifest["manifest_sha256"] = cloud._canonical_sha256(
        {k: v for k, v in manifest.items() if k != "manifest_sha256"}
    )
    path.write_text(json.dumps(body))
    config = command.load_configuration(path)
    execution = str(uuid4())
    snapshot = Snapshot(config.scope, execution, NOW, NOW, "success", True, b"[]")
    prepare(
        config.scope,
        execution,
        config.bundle_root,
        collect=lambda: snapshot,
        binding=device_binding(config.scope, device, source="Intune"),
    )
    monkeypatch.setattr(
        command.httpx,
        "Client",
        lambda **kw: pytest.fail("Legacy scope accessed network"),
    )
    monkeypatch.setattr(
        command,
        "LocalCertificateResolver",
        lambda **kw: pytest.fail("Legacy scope accessed credential"),
    )
    monkeypatch.setattr(
        command, "ingest_exposure", lambda snapshot, pin: {"outcome": snapshot.outcome}
    )
    assert command.run(config, execution, device_snapshot=device) == {
        "outcome": "success"
    }
    assert command.run(
        config,
        str(uuid4()),
        device_snapshot=device,
        allow_network=True,
        now=lambda: NOW + timedelta(minutes=1),
    ) == {"outcome": "failure"}
