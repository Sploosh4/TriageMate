"""Synthetic retained evidence; no Microsoft requests or VM execution."""

from copy import deepcopy
import hashlib
import json
from uuid import uuid4

import pytest

from .contract import DeviceBinding
from .os_update_evidence import API, CONTRACT, LABELS, canonical, evaluate

OLD, CURRENT = "a" * 40, "b" * 40


def source(value):
    text = canonical(value)
    return {"text": text, "sha256": hashlib.sha256(text.encode()).hexdigest()}


def sample(binding=None):
    binding = binding or DeviceBinding(*(str(uuid4()) for _ in range(3)))
    native = {
        "tenant_id": binding.tenant_id,
        "device_id": binding.device_id,
        "machine_guid": binding.machine_guid,
        "observed_at": "2026-09-21T04:00:00Z",
        "release": "25H2",
        "build": "26200",
        "ubr": 9457,
        "architecture": "AMD64",
    }
    installed = {
        "identity": deepcopy(native),
        "observed_at": "2026-09-21T03:00:00Z",
        "rows": [{"HotFixID": "KB5129195", "Description": "Security Update"}],
    }
    devices = []
    for device, first, seen in ((OLD, "12", "15"), (CURRENT, "16", "21")):
        devices.append(
            {
                "id": device,
                "aadDeviceId": binding.device_id,
                "osPlatform": "Windows11",
                "osBuild": 26200,
                "version": "25H2",
                "osProcessor": "x64",
                "osArchitecture": "64-bit",
                "firstSeen": f"2026-09-{first}T00:00:00Z",
                "lastSeen": f"2026-09-{seen}T01:00:00Z",
            }
        )
    payloads = {
        "devices": devices,
        "software-inventory": [
            {
                "deviceId": device,
                "softwareVendor": "microsoft",
                "softwareName": "windows_11",
                "softwareVersion": version,
                "numberOfWeaknesses": count,
            }
            for device, version, count in (
                (OLD, "10.0.26200.6584", 1),
                (CURRENT, "10.0.26200.9457", 0),
            )
        ],
        "vulnerabilities": [
            {
                "deviceId": OLD,
                "softwareVendor": "microsoft",
                "softwareName": "windows_11",
                "softwareVersion": "10.0.26200.6584",
                "cveId": "CVE-2026-1000",
            }
        ],
        "current-missing-kbs": [],
    }
    sources = {"native": source(native), "installed": source(installed)}
    requests = []
    for label, route in LABELS.items():
        sources[label + "-0"] = source({"value": payloads[label]})
        requests.append(
            {
                "label": label,
                "complete": True,
                "count": len(payloads[label]),
                "pages": [
                    {
                        "url": API
                        + (route or f"/api/machines/{CURRENT}/getmissingkbs"),
                        "status": 200,
                        "started_at": "2026-09-21T11:00:00Z",
                        "finished_at": "2026-09-21T11:00:01Z",
                        "sha256": sources[label + "-0"]["sha256"],
                    }
                ],
            }
        )
    sources["requests"] = source(requests)
    return {
        "contract": CONTRACT,
        "origin": "synthetic",
        "collection_tenant_id": binding.tenant_id,
        "queried_kbs": ["KB5129195", "KB5124008"],
        "sources": sources,
    }, binding


def change(bundle, name, mutate):
    value = json.loads(bundle["sources"][name]["text"])
    mutate(value)
    bundle["sources"][name] = source(value)
    if name.endswith("-0"):
        requests = json.loads(bundle["sources"]["requests"]["text"])
        request = next(r for r in requests if r["label"] + "-0" == name)
        request["count"] = len(value["value"])
        request["pages"][0]["sha256"] = bundle["sources"][name]["sha256"]
        bundle["sources"]["requests"] = source(requests)


def result(bundle, binding):
    return evaluate(canonical(bundle).encode(), binding=binding, origin="synthetic")


def test_exact_dated_selection_preserves_old_identity_and_empty_source_result():
    bundle, binding = sample()
    report = result(bundle, binding)
    assert report["selected_native_device_id"] == CURRENT
    assert [r["state"] for r in report["providers"]] == [
        "historical_incompatible_os",
        "selected",
    ]
    assert report["missing_state"] == "none_reported"
    assert report["device_findings"] == []
    assert report["installed_updates"][0]["kb"] == "KB5129195"
    assert report["queried_kbs"] == ["KB5129195", "KB5124008"]
    assert report["native_observed_at"] != report["provider_observed_at"]


@pytest.mark.parametrize(
    "kind",
    [
        "foreign",
        "tamper",
        "old_endpoint",
        "count",
        "partial",
        "pagination",
        "stale",
        "native_arch",
        "installed_version",
        "tenant",
    ],
)
def test_incompatible_or_unverifiable_evidence_is_rejected(kind):
    bundle, binding = sample()
    if kind == "foreign":
        change(
            bundle,
            "devices-0",
            lambda x: x["value"][0].update(aadDeviceId=str(uuid4())),
        )
    elif kind == "tamper":
        bundle["sources"]["native"]["text"] += " "
    elif kind == "old_endpoint":
        change(
            bundle,
            "requests",
            lambda x: x[-1]["pages"][0].update(
                url=API + f"/api/machines/{OLD}/getmissingkbs"
            ),
        )
    elif kind == "count":
        change(bundle, "requests", lambda x: x[0].update(count=100))
    elif kind == "partial":
        change(bundle, "requests", lambda x: x[0].update(complete=False))
    elif kind == "pagination":
        change(
            bundle, "devices-0", lambda x: x.update({"@odata.nextLink": API + "/next"})
        )
    elif kind == "stale":
        change(bundle, "native", lambda x: x.update(observed_at="2026-09-19T00:00:00Z"))
    elif kind == "native_arch":
        change(bundle, "native", lambda x: x.update(architecture="ARM64"))
    elif kind == "installed_version":
        change(bundle, "installed", lambda x: x["identity"].update(ubr=6584))
    elif kind == "tenant":
        bundle["collection_tenant_id"] = str(uuid4())
    with pytest.raises(ValueError):
        result(bundle, binding)


@pytest.mark.parametrize(
    "kind",
    [
        "two_versions",
        "provider_arch",
        "contemporary_old",
        "missing_os",
        "merged",
        "duplicate_flag",
    ],
)
def test_ambiguous_provider_evidence_remains_unresolved(kind):
    bundle, binding = sample()
    if kind == "two_versions":
        change(
            bundle,
            "software-inventory-0",
            lambda x: x["value"][0].update(softwareVersion="10.0.26200.9457"),
        )
    elif kind == "provider_arch":
        change(bundle, "devices-0", lambda x: x["value"][1].update(osProcessor="arm64"))
    elif kind == "contemporary_old":
        change(
            bundle,
            "devices-0",
            lambda x: x["value"][0].update(lastSeen="2026-09-21T00:00:00Z"),
        )
    elif kind == "missing_os":
        change(bundle, "software-inventory-0", lambda x: x.update(value=[]))
    elif kind == "merged":
        change(
            bundle, "devices-0", lambda x: x["value"][1].update(mergedIntoMachineId=OLD)
        )
    else:
        change(
            bundle,
            "devices-0",
            lambda x: x["value"][1].update(isPotentialDuplication=True),
        )
    report = result(bundle, binding)
    assert report["identity_state"] == "unresolved"
    assert report["missing_state"] == "identity_unresolved"
    assert report["windows_findings"] is None


def test_nonempty_missing_updates_are_device_bound_and_not_called_installed():
    bundle, binding = sample()
    change(
        bundle,
        "current-missing-kbs-0",
        lambda x: x["value"].append({"id": "5129999", "productsNames": ["windows_11"]}),
    )
    report = result(bundle, binding)
    assert report["missing_state"] == "reported_missing"
    assert report["missing_updates"][0]["id"] == "5129999"
    assert [r["kb"] for r in report["installed_updates"]] == ["KB5129195"]


def test_duplicate_json_keys_are_rejected():
    bundle, binding = sample()
    with pytest.raises(ValueError, match="Duplicate"):
        evaluate(b'{"contract":1,"contract":2}', binding=binding, origin="synthetic")


def test_native_submicrosecond_timestamp_uses_postgres_precision():
    from .os_update_evidence import instant

    assert (
        instant("2026-09-21T03:42:44.0235029Z").isoformat()
        == "2026-09-21T03:42:44.023503+00:00"
    )
    assert (
        instant("2026-09-21T03:42:44.9999999Z").isoformat()
        == "2026-09-21T03:42:45+00:00"
    )
