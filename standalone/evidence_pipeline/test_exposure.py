from dataclasses import replace
from datetime import datetime, timezone
import json
from uuid import uuid4

import pytest

from standalone.evidence_pipeline.contracts import Snapshot, SourceScope
from standalone.evidence_pipeline.parsing.exposure import (
    normalize_software,
    normalize_findings,
    software,
)


def snapshot(source, kind, records):
    now = datetime(2026, 9, 12, tzinfo=timezone.utc)
    scope = SourceScope(
        str(uuid4()),
        source,
        kind,
        "synthetic",
        "synthetic",
        "generated fixture",
        str(uuid4()),
    )
    return Snapshot(
        scope, str(uuid4()), now, now, "success", True, json.dumps(records).encode()
    )


def test_inventory_retains_software_without_cves_and_does_not_require_uuid_app_id():
    device = str(uuid4())
    source = snapshot(
        "Intune",
        "software",
        [
            {
                "id": "opaque-microsoft-app-id",
                "displayName": "Synthetic application",
                "version": "1",
                "deviceCount": 1,
            },
            {
                "id": "unassociated-app",
                "displayName": "Other application",
                "deviceCount": 0,
            },
        ],
    )
    items = normalize_software(
        source, {"opaque-microsoft-app-id": (device,), "unassociated-app": ()}, {device}
    )
    assert len(items) == 2
    assert items[0].native_device_ids == (device,)
    assert items[1].native_device_ids == ()
    assert items[1].software.version is None


@pytest.mark.parametrize(
    "associations,count",
    [({}, 1), ({"app": ()}, 1), ({"app": ("not-a-guid",)}, 1), ({"app": ()}, True)],
)
def test_incomplete_or_invalid_associations_rejected(associations, count):
    source = snapshot(
        "Intune",
        "software",
        [{"id": "app", "displayName": "Synthetic application", "deviceCount": count}],
    )
    with pytest.raises(ValueError):
        normalize_software(source, associations, set())


def test_unknown_and_duplicate_devices_rejected():
    device = str(uuid4())
    source = snapshot(
        "Intune", "software", [{"id": "app", "displayName": "Synthetic application"}]
    )
    with pytest.raises(ValueError):
        normalize_software(source, {"app": (device,)}, set())
    with pytest.raises(ValueError):
        normalize_software(source, {"app": (device, device)}, {device})


def test_uncollected_apps_are_not_silently_ignored():
    with pytest.raises(ValueError):
        normalize_software(snapshot("Intune", "software", []), {"app": ()}, set())


def test_software_identity_distinguishes_version_and_null():
    a = software("Product", None, None)
    assert a == software("Product", None, None)
    assert a.id != software("Product", "null", None).id
    assert (
        software("Product", "Vendor", "1").id != software("Product", "Vendor", "2").id
    )


def finding(**changes):
    return {
        "id": "finding-1",
        "machineId": "machine-a",
        "cveId": "CVE-2026-10001",
        "productName": "Synthetic product",
        "productVendor": "Synthetic vendor",
        "productVersion": "1",
        "severity": "High",
        **changes,
    }


def test_findings_keep_source_patch_reference_and_unknown_fix_separate():
    source = snapshot(
        "Defender",
        "findings",
        [
            finding(fixingKbId="KB000001"),
            finding(id="finding-2", cveId="CVE-2026-10002", fixingKbId=None),
        ],
    )
    first, second = normalize_findings(source, {"machine-a"})
    assert first.fixing_patch_reference == "KB000001"
    assert second.fixing_patch_reference is None
    assert first.source_severity_label == "High"
    assert first.software == second.software


@pytest.mark.parametrize(
    "changes",
    [
        {"cveId": "not-cve"},
        {"machineId": "unknown"},
        {"productName": None},
        {"id": None},
    ],
)
def test_invalid_finding_prevents_complete_materialization(changes):
    with pytest.raises(ValueError):
        normalize_findings(
            snapshot("Defender", "findings", [finding(**changes)]), {"machine-a"}
        )


def test_duplicate_finding_id_rejected_even_if_payload_matches():
    with pytest.raises(ValueError):
        normalize_findings(
            snapshot("Defender", "findings", [finding(), finding()]), {"machine-a"}
        )


def test_partial_or_wrong_input_never_materializes():
    source = snapshot("Defender", "findings", [finding()])
    with pytest.raises(ValueError):
        normalize_findings(
            replace(source, complete=False, outcome="partial"), {"machine-a"}
        )
    with pytest.raises(ValueError):
        normalize_software(source, {}, set())
