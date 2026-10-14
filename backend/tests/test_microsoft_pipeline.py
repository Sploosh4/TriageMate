"""Synthetic HTTP and signed tokens exercise the new connection-scoped bridge."""

from dataclasses import replace
from uuid import uuid4

import httpx
import pytest

from standalone.evidence_pipeline.contracts import SourceScope
from standalone.evidence_pipeline.parsing.devices import normalize_devices
from microsoft_evidence.cloud import PreparedCollectionContext
from microsoft_evidence.pipeline import collect_devices, connection_scope
from microsoft_evidence.transport import MicrosoftHttpTransport, MicrosoftTransportError
from tests.test_microsoft_live_authority import NOW, _live_prepared
from tests.test_microsoft_transport import _lease


def scope():
    return SourceScope(
        str(uuid4()),
        "Entra",
        "devices",
        "synthetic-test-connection",
        "lab",
        "Explicitly synthetic HTTP fixture; no real tenant",
        str(uuid4()),
    )


def test_signed_connection_authority_collects_and_normalizes_all_pages():
    source = scope()
    prepared = _live_prepared(scope=connection_scope(source))
    assert (
        PreparedCollectionContext.model_validate_json(prepared.model_dump_json())
        == prepared
    )
    assert "agency_id" not in prepared.model_dump_json()
    calls = []
    registration = str(uuid4())
    native = str(uuid4())

    def handler(request):
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(
                200,
                json={
                    "value": [
                        {
                            "id": native,
                            "deviceId": registration,
                            "accountEnabled": False,
                        }
                    ],
                    "@odata.nextLink": "https://graph.microsoft.com/v1.0/devices?$skiptoken=next",
                },
            )
        return httpx.Response(200, json={"value": []})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        snapshot = collect_devices(
            scope=source,
            execution_id=str(uuid4()),
            prepared=prepared,
            token=_lease(prepared),
            transport=MicrosoftHttpTransport(client=client, now=lambda: NOW),
            now=lambda: NOW,
        )
    assert snapshot.complete and snapshot.scope.origin == "lab"
    assert len(calls) == 2
    assert "$select" in calls[0].url.params
    (device,) = normalize_devices(snapshot)
    assert device.native_id == native and device.registration_id == registration
    assert device.observation()["account_enabled"] is False


@pytest.mark.parametrize(
    "changes",
    (
        {"connection_id": str(uuid4())},
        {"tenant_id": str(uuid4())},
        {"scope_reference": "other"},
        {"provenance": "other"},
        {"origin": "synthetic"},
        {"input_kind": "software"},
        {"source": "Intune"},
    ),
)
def test_scope_mismatch_is_rejected_before_http(changes):
    source = scope()
    prepared = _live_prepared(scope=connection_scope(source))
    calls = []
    with httpx.Client(
        transport=httpx.MockTransport(lambda request: calls.append(request))
    ) as client:
        with pytest.raises(ValueError):
            collect_devices(
                scope=replace(source, **changes),
                execution_id=str(uuid4()),
                prepared=prepared,
                token=_lease(prepared),
                transport=MicrosoftHttpTransport(client=client, now=lambda: NOW),
                now=lambda: NOW,
            )
    assert calls == []


def test_verified_lease_cannot_move_to_another_connection():
    first = scope()
    second = replace(first, connection_id=str(uuid4()))
    original = _live_prepared(scope=connection_scope(first))
    # Preserve every other authority field to isolate the connection fingerprint.
    changed = original.model_copy(update={"scope": connection_scope(second)})
    calls = []
    with httpx.Client(
        transport=httpx.MockTransport(lambda request: calls.append(request))
    ) as client:
        with pytest.raises(MicrosoftTransportError, match="authority does not match"):
            collect_devices(
                scope=second,
                execution_id=str(uuid4()),
                prepared=changed,
                token=_lease(original),
                transport=MicrosoftHttpTransport(client=client, now=lambda: NOW),
                now=lambda: NOW,
            )
    assert calls == []


@pytest.mark.parametrize(
    "product,path,audience,roles,wire,expected",
    (
        (
            "Intune",
            "/v1.0/deviceManagement/managedDevices",
            "https://graph.microsoft.com",
            ("DeviceManagementManagedDevices.Read.All",),
            {
                "id": "10000000-0000-4000-8000-000000000001",
                "osVersion": "10.0.26100",
                "lastSyncDateTime": "2026-08-25T00:00:00Z",
            },
            {"os_version": "10.0.26100", "last_sync": "2026-08-25T00:00:00+00:00"},
        ),
        (
            "Defender",
            "/api/machines",
            "https://api.security.microsoft.com",
            ("Machine.Read.All",),
            {
                "id": "synthetic-defender-native-id",
                "osBuild": 26100,
                "healthStatus": "Active",
                "ipAddresses": [{"ipAddress": "192.0.2.1"}],
                "vmMetadata": {"synthetic_extra": True},
            },
            {"os_build": "26100", "sensor_health": "Active"},
        ),
    ),
)
def test_other_device_sources_use_their_endpoint_and_native_fields(
    product, path, audience, roles, wire, expected
):
    source = replace(scope(), source=product)
    prepared = _live_prepared(
        scope=connection_scope(source),
        source_input=(product.lower(), path, audience, roles),
    )
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json={"value": [wire], "@odata.count": 1})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        snapshot = collect_devices(
            scope=source,
            execution_id=str(uuid4()),
            prepared=prepared,
            token=_lease(prepared),
            transport=MicrosoftHttpTransport(client=client, now=lambda: NOW),
            now=lambda: NOW,
        )
    (device,) = normalize_devices(snapshot)
    assert b"ipAddresses" not in snapshot.payload
    assert b"vmMetadata" not in snapshot.payload
    for key, value in expected.items():
        assert device.observation()[key] == value
    assert str(calls[0].url).startswith(audience + path)
    assert ("$select" in calls[0].url.params) == (product == "Intune")


@pytest.mark.parametrize(
    "payload,status",
    (({"value": [{"id": "invalid-guid"}]}, 200), ({"error": "synthetic-failure"}, 403)),
)
def test_invalid_or_failed_collection_never_returns_complete_snapshot(payload, status):
    source = scope()
    prepared = _live_prepared(scope=connection_scope(source))
    with httpx.Client(
        transport=httpx.MockTransport(lambda _: httpx.Response(status, json=payload))
    ) as client:
        with pytest.raises((ValueError, MicrosoftTransportError)):
            collect_devices(
                scope=source,
                execution_id=str(uuid4()),
                prepared=prepared,
                token=_lease(prepared),
                transport=MicrosoftHttpTransport(client=client, now=lambda: NOW),
                now=lambda: NOW,
            )


@pytest.mark.parametrize("status", (200, 403))
def test_device_collection_bundle_replays_success_or_failure_without_http(
    tmp_path, status
):
    from microsoft_evidence.pipeline import prepare_device_collection

    source = scope()
    prepared = _live_prepared(scope=connection_scope(source))
    lease = _lease(prepared)
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    execution = str(uuid4())
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(status, json={"value": []})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        args = dict(
            scope=source,
            execution_id=execution,
            root=root,
            prepared=prepared,
            token=lease,
            transport=MicrosoftHttpTransport(client=client, now=lambda: NOW),
            now=lambda: NOW,
        )
        first = prepare_device_collection(**args)
        second = prepare_device_collection(**args)
    assert first == second
    assert first.complete == (status == 200)
    assert len(calls) == 1
    stored = b"".join(path.read_bytes() for path in (root / execution).iterdir())
    assert lease.authorization_header().encode() not in stored
    assert b"Bearer" not in stored
    if status == 403:
        assert first.error_code == "microsoft_access_forbidden"
        assert first.payload == b""


def test_collected_failure_and_recovery_reach_database_and_replay(tmp_path):
    from microsoft_evidence.pipeline import collect_and_ingest_devices
    from standalone.evidence_pipeline.commands import register
    from standalone.evidence_pipeline.test_commands import cleanup
    from standalone.evidence_pipeline.runtime import local_database

    source = scope()
    prepared = _live_prepared(scope=connection_scope(source))
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(403 if len(calls) == 1 else 200, json={"value": []})

    try:
        register(source)
        with httpx.Client(transport=httpx.MockTransport(handler)) as client:
            args = dict(
                scope=source,
                root=root,
                prepared=prepared,
                token=_lease(prepared),
                transport=MicrosoftHttpTransport(client=client, now=lambda: NOW),
                now=lambda: NOW,
            )
            failed_id = str(uuid4())
            assert (
                collect_and_ingest_devices(execution_id=failed_id, **args)["outcome"]
                == "failure"
            )
            assert collect_and_ingest_devices(execution_id=failed_id, **args)[
                "replayed"
            ]
            from datetime import timedelta

            args["now"] = lambda: NOW + timedelta(seconds=1)
            recovered_id = str(uuid4())
            assert (
                collect_and_ingest_devices(execution_id=recovered_id, **args)["outcome"]
                == "success"
            )
            assert collect_and_ingest_devices(execution_id=recovered_id, **args)[
                "replayed"
            ]
        assert len(calls) == 2
        from contextlib import closing

        with (
            closing(local_database().connect(reader=True)) as conn,
            conn.cursor() as cursor,
        ):
            cursor.execute(
                "SELECT outcome,count(*) FROM evidence.collection_attempts WHERE connection_id=%s GROUP BY outcome",
                (source.connection_id,),
            )
            assert dict(cursor.fetchall()) == {"failure": 1, "success": 1}
            cursor.execute(
                "SELECT status FROM evidence.notifications WHERE connection_id=%s",
                (source.connection_id,),
            )
            assert cursor.fetchall() == [("resolved",)]
    finally:
        cleanup(source)


@pytest.mark.parametrize(
    "records", ("matching", "empty", "different", "duplicate", "continuation")
)
@pytest.mark.parametrize("provider", ["Defender", "Entra"])
def test_single_device_is_filtered_and_cannot_expand(records, provider):
    native_id = "a" * 40 if provider == "Defender" else str(uuid4())
    source = replace(
        scope(), source=provider, scope_reference="native-device-id:" + native_id
    )
    prepared = _live_prepared(
        scope=connection_scope(source),
        source_input=(
            "defender",
            "/api/machines",
            "https://api.security.microsoft.com",
            ("Machine.Read.All",),
        )
        if provider == "Defender"
        else (
            "entra",
            "/v1.0/devices",
            "https://graph.microsoft.com",
            ("Device.Read.All",),
        ),
    )
    calls = []

    def handler(request):
        calls.append(request)
        assert request.url.params["$filter"] == f"id eq '{native_id}'"
        items = (
            []
            if records == "empty"
            else [{"id": "b" * 40 if records == "different" else native_id}]
        )
        if records == "duplicate":
            items *= 2
        body = {"value": items}
        if records == "continuation":
            body["@odata.nextLink"] = (
                "https://api.security.microsoft.com/api/machines?$skiptoken=unfiltered"
            )
        return httpx.Response(200, json=body)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:

        def collect():
            return collect_devices(
                scope=source,
                execution_id=str(uuid4()),
                prepared=prepared,
                token=_lease(prepared),
                transport=MicrosoftHttpTransport(client=client, now=lambda: NOW),
                now=lambda: NOW,
            )

        if records in ("different", "duplicate", "continuation"):
            with pytest.raises((ValueError, MicrosoftTransportError)):
                collect()
        else:
            snapshot = collect()
            assert len(normalize_devices(snapshot)) == (records == "matching")
    assert len(calls) == 1


@pytest.mark.parametrize(
    "reference",
    (
        "native-device-id",
        "native-device-id:",
        "native-device-id:a' or true",
        "native-device-id:" + "A" * 40,
    ),
)
def test_invalid_single_device_selection_fails_before_http(reference):
    source = replace(scope(), source="Defender", scope_reference=reference)
    prepared = _live_prepared(
        scope=connection_scope(source),
        source_input=(
            "defender",
            "/api/machines",
            "https://api.security.microsoft.com",
            ("Machine.Read.All",),
        ),
    )
    calls = []
    with httpx.Client(
        transport=httpx.MockTransport(lambda request: calls.append(request))
    ) as client:
        with pytest.raises(ValueError, match="single-device"):
            collect_devices(
                scope=source,
                execution_id=str(uuid4()),
                prepared=prepared,
                token=_lease(prepared),
                transport=MicrosoftHttpTransport(client=client, now=lambda: NOW),
                now=lambda: NOW,
            )
    assert not calls


@pytest.mark.parametrize(
    "response_kind",
    ["matching", "wrong_id", "collection", "continuation", "extra_field"],
)
def test_single_intune_device_uses_exact_resource_and_rejects_other_shapes(
    response_kind,
):
    native_id = str(uuid4())
    source = replace(
        scope(), source="Intune", scope_reference="native-device-id:" + native_id
    )
    path = "/v1.0/deviceManagement/managedDevices/" + native_id
    prepared = _live_prepared(
        scope=connection_scope(source),
        source_input=(
            "intune",
            path,
            "https://graph.microsoft.com",
            ("DeviceManagementManagedDevices.Read.All",),
        ),
    )
    calls = []

    def handler(request):
        calls.append(request)
        assert request.url.path == path
        assert "$filter" not in request.url.params
        assert "$select" in request.url.params
        body = {"id": native_id, "@odata.context": "synthetic-context"}
        if response_kind == "wrong_id":
            body["id"] = str(uuid4())
        if response_kind == "collection":
            body = {"value": [body]}
        if response_kind == "continuation":
            body["@odata.nextLink"] = (
                "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices"
            )
        if response_kind == "extra_field":
            body["unrequestedPrivateField"] = "synthetic-only"
        return httpx.Response(200, json=body)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:

        def collect():
            return collect_devices(
                scope=source,
                execution_id=str(uuid4()),
                prepared=prepared,
                token=_lease(prepared),
                transport=MicrosoftHttpTransport(client=client, now=lambda: NOW),
                now=lambda: NOW,
            )

        if response_kind == "matching":
            assert normalize_devices(collect())[0].native_id == native_id
        else:
            with pytest.raises((ValueError, MicrosoftTransportError)):
                collect()
    assert len(calls) == 1


@pytest.mark.parametrize("unexpected", [False, True])
def test_explicit_defender_allowlist_rejects_unexpected_inventory(unexpected):
    source = replace(
        scope(),
        source="Defender",
        scope_reference="allowed-native-device-ids:" + "a" * 40,
    )
    prepared = _live_prepared(
        scope=connection_scope(source),
        source_input=(
            "defender",
            "/api/machines",
            "https://api.security.microsoft.com",
            ("Machine.Read.All",),
        ),
    )
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200, json={"value": [{"id": ("b" if unexpected else "a") * 40}]}
            )
        )
    ) as client:

        def collect():
            return collect_devices(
                scope=source,
                execution_id=str(uuid4()),
                prepared=prepared,
                token=_lease(prepared),
                transport=MicrosoftHttpTransport(client=client, now=lambda: NOW),
                now=lambda: NOW,
            )

        if unexpected:
            with pytest.raises(ValueError, match="explicit device allowlist"):
                collect()
        else:
            assert len(collect().records()) == 1


@pytest.mark.parametrize(
    "reference",
    [
        "allowed-native-device-ids",
        "allowed-native-device-ids:",
        "allowed-native-device-ids:" + "a" * 40 + "," + "a" * 40,
        "allowed-native-device-ids:" + "B" * 40,
    ],
)
def test_invalid_device_allowlist_is_rejected(reference):
    from microsoft_evidence.pipeline import selected_device_allowlist

    with pytest.raises(ValueError, match="allowlist"):
        selected_device_allowlist(
            replace(scope(), source="Defender", scope_reference=reference)
        )
