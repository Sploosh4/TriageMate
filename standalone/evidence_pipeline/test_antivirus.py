"""Synthetic source-contract checks; no live tenant or database required."""

from dataclasses import replace

import pytest

from standalone.evidence_pipeline.parsing.antivirus import normalize_antivirus
from .test_exposure import snapshot


def health(**changes):
    return {"id": "synthetic-health-1", "machineId": "synthetic-device", **changes}


def normalize(*records):
    return normalize_antivirus(
        snapshot("Defender", "antivirus", list(records)), {"synthetic-device"}
    )


@pytest.mark.parametrize(
    "status,expected",
    [
        ("True", True),
        ("False", False),
        ("Unknown", None),
        (None, None),
        ("", None),
        ("Future status", None),
        ("true", None),
    ],
)
@pytest.mark.parametrize("component", ["Signature", "Engine", "Platform"])
def test_status_text_preserves_unknown_separately_from_boolean(
    status, expected, component
):
    row = normalize(health(**{"avIs" + component + "UpToDate": status}))[
        0
    ].observation()
    assert row[component.lower() + "_status"] == status
    assert row[component.lower() + "_current"] is expected


def test_modes_errors_and_timestamps_are_source_evidence():
    row = normalize(
        health(
            avMode="0",
            fullScanResult="",
            quickScanError="reported-error",
            lastSeenTime="2026-09-13T08:00:00Z",
            fullScanTime=None,
            rbacGroupId=2**63 - 1,
        )
    )[0].observation()
    assert row["mode"] == "0"
    assert row["full_scan_result"] == ""
    assert row["quick_scan_error"] == "reported-error"
    assert row["last_seen_at"] == "2026-09-13T08:00:00+00:00"
    assert row["full_scan_at"] is None
    assert row["source_rbac_group_id"] == 2**63 - 1
    assert normalize(health(avMode=""))[0].observation()["mode"] == ""


def test_distinct_records_for_one_device_survive_in_canonical_order():
    records = normalize(health(id="b", avMode="1"), health(id="a", avMode="0"))
    assert [row.source_record_id for row in records] == ["a", "b"]
    assert [row.observation()["mode"] for row in records] == ["0", "1"]
    assert normalize() == ()


@pytest.mark.parametrize(
    "changes",
    [
        {"id": None},
        {"id": ""},
        {"machineId": "unknown-device"},
        {"avIsSignatureUpToDate": True},
        {"avIsEngineUpToDate": 0},
        {"avMode": 0},
        {"fullScanError": []},
        {"osKind": "\x00"},
        {"osVersion": "x" * 8193},
        {"lastSeenTime": "not-a-time"},
        {"quickScanTime": "2026-09-13T08:00:00"},
        {"rbacGroupId": True},
        {"rbacGroupId": -1},
        {"rbacGroupId": 2**63},
        {"rbacGroupId": 1.5},
        {"unexpectedColumn": "must not enter durable evidence"},
    ],
)
def test_invalid_source_values_fail_the_complete_snapshot(changes):
    with pytest.raises(ValueError):
        normalize(health(**changes))


def test_duplicate_source_ids_are_rejected():
    with pytest.raises(ValueError, match="Duplicate"):
        normalize(health(), health(avMode="1"))


def test_wrong_source_kind_and_incomplete_snapshots_are_rejected():
    original = snapshot("Defender", "antivirus", [health()])
    for invalid in (
        replace(original, outcome="partial", complete=False),
        replace(original, scope=replace(original.scope, source="Intune")),
        replace(original, scope=replace(original.scope, input_kind="devices")),
    ):
        with pytest.raises(ValueError):
            normalize_antivirus(invalid, {"synthetic-device"})
