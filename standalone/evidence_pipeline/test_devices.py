from datetime import datetime, timezone
import json
from uuid import uuid4

import pytest

from standalone.evidence_pipeline.contracts import Snapshot, SourceScope
from standalone.evidence_pipeline.parsing.devices import (
    normalize_devices,
    match_device_groups,
)


def make(source, records, tenant=None, connection=None):
    scope = SourceScope(
        connection or str(uuid4()),
        source,
        "devices",
        "synthetic-test",
        "synthetic",
        "generated fixture",
        tenant or str(uuid4()),
    )
    now = datetime(2026, 9, 12, tzinfo=timezone.utc)
    return Snapshot(
        scope, str(uuid4()), now, now, "success", True, json.dumps(records).encode()
    )


def test_mapping_preserves_false_unknown_and_provider_time():
    snapshot = make(
        "Entra",
        [
            {
                "id": str(uuid4()),
                "accountEnabled": False,
                "isManaged": False,
                "displayName": "",
                "approximateLastSignInDateTime": "2026-09-11T08:00:00+08:00",
            }
        ],
    )
    (device,) = normalize_devices(snapshot)
    values = device.observation()
    assert values["account_enabled"] is False
    assert values["managed_flag"] is False
    assert values["compliant_flag"] is None
    assert values["display_name"] is None
    assert values["approximate_last_sign_in"] == "2026-09-11T00:00:00+00:00"
    assert "observed_at" not in values
    assert device.identity_issue == "missing_registration_id"


def test_all_sources_share_only_supported_device_identifier():
    tenant, shared = str(uuid4()), str(uuid4())
    sources = [
        ("Entra", "deviceId"),
        ("Intune", "azureADDeviceId"),
        ("Defender", "aadDeviceId"),
    ]
    batches = []
    for source, field in sources:
        snapshot = make(source, [{"id": str(uuid4()), field: shared.upper()}], tenant)
        batches.append((snapshot, normalize_devices(snapshot)))
    links = match_device_groups(batches)
    assert len({computer for computer, _ in links.values()}) == 1
    assert {basis for _, basis in links.values()} == {"microsoft_registration_id"}


def test_shared_guid_does_not_cross_tenants():
    shared = str(uuid4())
    a = make("Entra", [{"id": str(uuid4()), "deviceId": shared}])
    b = make("Intune", [{"id": str(uuid4()), "azureADDeviceId": shared}])
    links = match_device_groups([(a, normalize_devices(a)), (b, normalize_devices(b))])
    assert len({computer for computer, _ in links.values()}) == 2


def test_duplicate_shared_ids_are_visible_and_never_merged():
    tenant, shared = str(uuid4()), str(uuid4())
    a = make(
        "Entra", [{"id": str(uuid4()), "deviceId": shared} for _ in range(2)], tenant
    )
    b = make("Intune", [{"id": str(uuid4()), "azureADDeviceId": shared}], tenant)
    links = match_device_groups([(a, normalize_devices(a)), (b, normalize_devices(b))])
    assert len({computer for computer, _ in links.values()}) == 3
    assert {basis for _, basis in links.values()} == {"ambiguous_registration_id"}


@pytest.mark.parametrize(
    "shared", [None, "", "invalid", "00000000-0000-0000-0000-000000000000"]
)
def test_invalid_shared_id_retains_computer_without_hostname_merge(shared):
    snapshot = make(
        "Intune",
        [
            {"id": str(uuid4()), "deviceName": "same-name", "azureADDeviceId": shared}
            for _ in range(2)
        ],
    )
    devices = normalize_devices(snapshot)
    assert len(devices) == 2
    assert all(device.registration_id is None for device in devices)
    links = match_device_groups([(snapshot, devices)])
    assert len({computer for computer, _ in links.values()}) == 2


@pytest.mark.parametrize(
    "fields",
    [
        {"isManaged": "false"},
        {"accountEnabled": 0},
        {"approximateLastSignInDateTime": "2026-09-12"},
        {"displayName": {}},
    ],
)
def test_bad_field_prevents_whole_snapshot_materialization(fields):
    with pytest.raises(ValueError):
        normalize_devices(
            make("Entra", [{"id": str(uuid4())}, {"id": str(uuid4()), **fields}])
        )


def test_duplicate_native_id_and_multiple_current_snapshots_rejected():
    raw = {"id": str(uuid4())}
    with pytest.raises(ValueError):
        normalize_devices(make("Intune", [raw, raw]))
    snapshot = make("Intune", [raw])
    devices = normalize_devices(snapshot)
    with pytest.raises(ValueError):
        match_device_groups([(snapshot, devices), (snapshot, devices)])


def test_replays_stable_but_meaningful_changes_hash_differently():
    raw = {"id": str(uuid4()), "osVersion": "1"}
    snapshot = make("Intune", [raw])
    (first,) = normalize_devices(snapshot)
    (repeated,) = normalize_devices(
        make("Intune", [raw], snapshot.scope.tenant_id, snapshot.scope.connection_id)
    )
    (changed,) = normalize_devices(
        make(
            "Intune",
            [{**raw, "osVersion": "2"}],
            snapshot.scope.tenant_id,
            snapshot.scope.connection_id,
        )
    )
    assert first == repeated
    assert first.provider_id == changed.provider_id
    assert first.content_hash != changed.content_hash


def test_defender_build_is_not_invented_cvss_or_classification():
    snapshot = make(
        "Defender",
        [
            {
                "id": "defender-native-id",
                "osBuild": 0,
                "osPlatform": "WindowsServer2025",
                "version": "24H2",
                "riskScore": "High",
            }
        ],
    )
    (device,) = normalize_devices(snapshot)
    assert device.observation()["os_build"] == "0"
    assert device.observation()["release_label"] == "24H2"
    assert "classification" not in device.observation()
    assert "risk_score" not in device.observation()


@pytest.mark.parametrize("value", [None, "", "   "])
def test_absent_architecture_preserves_historical_content_hash(value):
    original = make("Defender", [{"id": "synthetic-architecture"}])
    extended = make(
        "Defender",
        [
            {
                "id": "synthetic-architecture",
                "osArchitecture": value,
                "osProcessor": value,
            }
        ],
    )
    (before,) = normalize_devices(original)
    (after,) = normalize_devices(extended)
    assert before.content_hash == after.content_hash
    assert "os_architecture" not in after.observation()
    assert "os_processor" not in after.observation()


def test_architecture_retains_source_values_and_changes_content_hash():
    (before,) = normalize_devices(make("Defender", [{"id": "synthetic-architecture"}]))
    (after,) = normalize_devices(
        make(
            "Defender",
            [
                {
                    "id": "synthetic-architecture",
                    "osArchitecture": "64-bit",
                    "osProcessor": "x64",
                }
            ],
        )
    )
    assert after.observation()["os_architecture"] == "64-bit"
    assert after.observation()["os_processor"] == "x64"
    assert before.content_hash != after.content_hash


@pytest.mark.parametrize("field", ["osArchitecture", "osProcessor"])
def test_architecture_rejects_non_text(field):
    with pytest.raises(ValueError):
        normalize_devices(
            make("Defender", [{"id": "synthetic-architecture", field: 64}])
        )


@pytest.mark.parametrize(
    "source,field",
    [
        ("Entra", "approximateLastSignInDateTime"),
        ("Intune", "lastSyncDateTime"),
        ("Defender", "lastSeen"),
    ],
)
def test_device_normalization_rejects_offset_minute_overflow(source, field):
    snapshot = make(source, [{"id": str(uuid4()), field: "2026-09-21T00:30:00+00:60"}])
    with pytest.raises(ValueError, match="Invalid timestamp"):
        normalize_devices(snapshot)
