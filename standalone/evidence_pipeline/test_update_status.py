"""Synthetic source mapping and uncertainty boundaries for update observations."""

from dataclasses import asdict, replace
import os
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

import pytest

from .test_exposure import snapshot
from standalone.evidence_pipeline.parsing.update_status import (
    normalize_missing_patches,
    normalize_update_status,
)


def test_standalone_import_needs_no_backend_pythonpath():
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    result = subprocess.run(
        [
            sys.executable,
            "-B",
            "-c",
            "import standalone.evidence_pipeline.persistence.exposure_store",
        ],
        cwd=Path(__file__).resolve().parents[2],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def missing(rows):
    return snapshot("Defender", "missing_patches", rows)


def update(rows):
    return snapshot("Intune", "update_status", rows)


def test_counts_are_retained_without_inventing_vulnerability_relationships():
    row = {
        "machineId": "opaque",
        "id": "KB123",
        "cveAddressed": 7,
        "machineMissedOn": 0,
    }
    result = normalize_missing_patches(missing([row]), {"opaque"})[0]
    assert result.reported_cve_count == 7
    assert result.reported_machine_count == 0
    assert result.title is None
    assert not {"cve_id", "installed", "resolved", "applicable"} & asdict(result).keys()


def test_same_patch_on_two_explicit_devices_remains_two_observations():
    rows = [{"machineId": machine, "id": "KB1"} for machine in ("a", "b")]
    result = normalize_missing_patches(missing(rows), {"a", "b"})
    assert len(result) == 2
    assert all(row.reported_cve_count is None for row in result)


@pytest.mark.parametrize("value", [-1, True, 1.5, "2", 2**63])
def test_invalid_counts_rejected(value):
    with pytest.raises(ValueError):
        normalize_missing_patches(
            missing([{"machineId": "a", "id": "KB1", "cveAddressed": value}]), {"a"}
        )


def test_missing_device_and_duplicate_patch_rows_rejected():
    row = {"machineId": "a", "id": "KB1"}
    for rows, known in [([row], {"b"}), ([row, row], {"a"}), ([{"id": "KB1"}], {"a"})]:
        with pytest.raises(ValueError):
            normalize_missing_patches(missing(rows), known)


def test_source_product_labels_preserved_without_software_identity_inference():
    row = {
        "machineId": "a",
        "id": "KB1",
        "productsNames": ["Synthetic product"],
        "url": "https://example.invalid/kb",
    }
    value = normalize_missing_patches(missing([row]), {"a"})[0]
    assert value.product_labels == ("Synthetic product",)
    assert value.url == row["url"]
    assert "software_id" not in asdict(value)


def test_update_status_retains_source_fields_and_does_not_copy_upn():
    device, policy = str(uuid4()), str(uuid4())
    row = {
        "DeviceId": device,
        "PolicyId": policy,
        "CurrentDeviceUpdateStatus": "installed",
        "AggregateState_loc": "Synthetic label",
        "UPN": "synthetic@example.invalid",
        "EventDateTimeUTC": "2026-09-12T10:00:00Z",
    }
    result = normalize_update_status(update([row]), {device})[0].observation()
    assert result["current_status"] == "installed"
    assert result["aggregate_state_localized"] == "Synthetic label"
    assert result["last_wu_scan_at"] is None
    assert result["event_time"] == "2026-09-12T10:00:00+00:00"
    assert not {"UPN", "installed", "fixed", "cve_id", "patch_id"} & result.keys()


def test_registration_does_not_substitute_for_explicit_device_binding():
    device, other, policy = (str(uuid4()) for _ in range(3))
    with pytest.raises(ValueError):
        normalize_update_status(
            update([{"DeviceId": device, "AADDeviceId": other, "PolicyId": policy}]),
            {other},
        )


def test_csv_utc_timestamps_preserve_raw_evidence_and_unset_scan_is_unknown():
    device = str(uuid4())
    row = {
        "DeviceId": device,
        "PolicyId": str(uuid4()),
        "EventDateTimeUTC": "2026-09-12 10:00:00.1234567",
        "LastWUScanTimeUTC": "0001-01-01 00:00:00.0000000",
        "AggregateState": "InProgress",
        "CurrentDeviceUpdateStatus": "1",
    }
    source = update([row])
    result = normalize_update_status(source, {device})[0].observation()
    assert result["event_time"] == "2026-09-12T10:00:00.123456+00:00"
    assert result["last_wu_scan_at"] is None
    assert result["current_status"] == "1"
    assert source.records()[0] == row
    assert not {"installed", "fixed", "patch_id"} & result.keys()


@pytest.mark.parametrize(
    "value",
    ["2026-02-30 10:00:00.0000000", "2026-09-12T10:00:00+01:00", 1],
)
def test_invalid_report_scan_timestamp_rejected(value):
    device = str(uuid4())
    with pytest.raises(ValueError):
        normalize_update_status(
            update(
                [
                    {
                        "DeviceId": device,
                        "PolicyId": str(uuid4()),
                        "LastWUScanTimeUTC": value,
                    }
                ]
            ),
            {device},
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("PolicyId", "bad"),
        ("EventDateTimeUTC", "2026-09-12T10:00:00"),
        ("CurrentDeviceUpdateStatus", 0),
        ("AADDeviceId", "bad"),
    ],
)
def test_bad_update_fields_rejected(field, value):
    device = str(uuid4())
    row = {"DeviceId": device, "PolicyId": str(uuid4()), field: value}
    with pytest.raises(ValueError):
        normalize_update_status(update([row]), {device})


def test_duplicate_policy_rows_are_not_silently_collapsed():
    device = str(uuid4())
    row = {"DeviceId": device, "PolicyId": str(uuid4())}
    with pytest.raises(ValueError):
        normalize_update_status(update([row, row]), {device})


@pytest.mark.parametrize(
    "adapter,source",
    [(normalize_missing_patches, missing), (normalize_update_status, update)],
)
def test_empty_complete_is_valid_but_partial_is_not_normalized(adapter, source):
    value = source([])
    assert adapter(value, set()) == ()
    with pytest.raises(ValueError):
        adapter(replace(value, complete=False, outcome="partial"), set())
    with pytest.raises(ValueError):
        adapter(replace(value, scope=replace(value.scope, input_kind="devices")), set())
