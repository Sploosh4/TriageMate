from uuid import uuid4

import pytest

from .test_update_status import missing, update
from standalone.evidence_pipeline.parsing.update_records import (
    content,
    rows,
    source_record_id,
)
from standalone.evidence_pipeline.parsing.update_status import (
    normalize_missing_patches,
    normalize_update_status,
)


def test_missing_patch_rows_have_exact_receipt_links_and_no_cve_edges():
    item = normalize_missing_patches(
        missing([{"machineId": "a", "id": "KB1", "cveAddressed": 12}]), {"a"}
    )[0]
    receipt, provider = str(uuid4()), str(uuid4())
    projected = dict(rows(item, receipt, provider, "2026-09-12T00:00:00+00:00"))
    assert set(projected) == {"patches", "device_missing_patches"}
    patch, observation = projected["patches"], projected["device_missing_patches"]
    assert observation["patch_id"] == patch["id"]
    assert patch["receipt_id"] == observation["receipt_id"] == receipt
    assert observation["provider_device_id"] == provider
    assert observation["reported_cve_count"] == 12
    assert patch["title"] == "KB1"
    assert patch["product_names"] is None
    assert content(item)["title"] is None
    assert (
        dict(rows(item, str(uuid4()), provider, None))["patches"]["id"] != patch["id"]
    )


def test_update_policy_projection_preserves_only_source_status_columns():
    device, policy, receipt, provider = (str(uuid4()) for _ in range(4))
    item = normalize_update_status(
        update(
            [
                {
                    "DeviceId": device,
                    "PolicyId": policy,
                    "CurrentDeviceUpdateStatus": "upToDate",
                }
            ]
        ),
        {device},
    )[0]
    table, row = rows(item, receipt, provider, None)[0]
    assert table == "update_policy_observations"
    assert row["source_device_id"] == device
    assert row["policy_id"] == policy
    assert row["provider_device_id"] == provider
    assert row["current_status"] == "upToDate"
    assert not {"resolved", "fixed", "patch_id", "cve_id"} & row.keys()


def test_source_keys_are_length_safe_and_device_specific():
    a, b = [
        normalize_missing_patches(
            missing([{"machineId": machine, "id": patch}]), {machine}
        )[0]
        for machine, patch in [("a:b", "c"), ("a", "b:c")]
    ]
    assert source_record_id(a) != source_record_id(b)


def test_projection_rejects_unknown_types_and_non_identifier_receipts():
    with pytest.raises(ValueError):
        source_record_id(object())
    item = normalize_missing_patches(missing([{"machineId": "a", "id": "KB1"}]), {"a"})[
        0
    ]
    with pytest.raises(ValueError):
        rows(item, "not-an-id", str(uuid4()), None)


def test_unknown_and_explicitly_empty_product_labels_remain_distinct():
    for source, expected in [(None, None), ([], [])]:
        item = normalize_missing_patches(
            missing([{"machineId": "a", "id": "KB1", "productsNames": source}]), {"a"}
        )[0]
        patch = dict(rows(item, str(uuid4()), str(uuid4()), None))["patches"]
        assert patch["product_names"] == expected
