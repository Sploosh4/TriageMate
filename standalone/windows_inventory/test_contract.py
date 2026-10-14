"""Synthetic inventory authority, losslessness and incomplete-output checks."""

from copy import deepcopy
from dataclasses import replace
import json

import pytest

from .contract import (
    APPX_PACKAGE_TYPES,
    CONTRACT,
    DeviceBinding,
    REGISTRY_SUFFIXES,
    observation_key,
    validate,
)


BINDING = DeviceBinding(
    "11111111-1111-4111-8111-111111111111",
    "22222222-2222-4222-8222-222222222222",
    "33333333-3333-4333-8333-333333333333",
)


def sample():
    registry = dict(
        kind="registry",
        native_id="HKEY_LOCAL_MACHINE" + REGISTRY_SUFFIXES[0] + r"\SyntheticApp",
        name="Synthetic app",
        version="01.002.0",
        publisher=None,
        install_date=None,
        system_component=0,
        release_type=None,
        parent_key_name=None,
    )
    appx = dict(
        kind="appx",
        native_id="SyntheticApp_01.002.0_x64__synthetic",
        name="Synthetic app",
        version="01.002.0",
        publisher="Synthetic publisher",
        family_name="SyntheticApp_synthetic",
        architecture="X64",
        is_framework=False,
        is_resource_package=False,
        non_removable=False,
        status="Ok",
        user_states=[dict(sid="S-1-5-21-1-2-3-1000", install_state="Staged")],
    )
    return dict(
        contract=CONTRACT,
        source="Windows inventory",
        started_at="2026-09-19T00:00:00Z",
        finished_at="2026-09-19T00:00:01Z",
        machine_guid=BINDING.machine_guid,
        tenant_id=BINDING.tenant_id,
        device_id=BINDING.device_id,
        complete=True,
        coverage=dict(
            registry_roots=[
                "Registry::HKEY_LOCAL_MACHINE" + s for s in REGISTRY_SUFFIXES
            ],
            loaded_user_sids=[],
            appx_scope="all-users",
            appx_package_types=list(APPX_PACKAGE_TYPES),
            unloaded_user_hives="not-read",
            portable_applications="not-enumerated",
            completeness="within-declared-contract",
        ),
        records=[registry, appx],
        record_count=2,
    )


def check(value, binding=BINDING):
    return validate(json.dumps(value).encode(), binding)


def test_lossless_observations_do_not_merge_packages_or_assert_applicability():
    value = sample()
    assert check(value) == value
    registry, appx = value["records"]
    assert registry["system_component"] == 0 and appx["is_framework"] is False
    assert registry["version"] == "01.002.0"
    assert appx["user_states"][0]["install_state"] == "Staged"
    assert observation_key(BINDING, registry) != observation_key(BINDING, appx)
    assert observation_key(BINDING, registry) == observation_key(
        BINDING, dict(registry, version="02")
    )
    assert "applicability" not in appx


@pytest.mark.parametrize("field", ["machine_guid", "tenant_id", "device_id"])
def test_device_identity_mismatch_rejected(field):
    other = replace(BINDING, **{field: "44444444-4444-4444-8444-444444444444"})
    with pytest.raises(ValueError, match="differs"):
        check(sample(), other)
    assert observation_key(BINDING, sample()["records"][0]) != observation_key(
        other, sample()["records"][0]
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("complete", False),
        ("complete", 1),
        ("record_count", 3),
        ("record_count", True),
        ("finished_at", "2026-09-18T00:00:00Z"),
        ("started_at", "2026-09-19T00:00:00"),
        ("source", "Intune"),
        ("contract", "unknown"),
    ],
)
def test_incomplete_or_mislabelled_envelope_rejected(field, value):
    data = sample()
    data[field] = value
    with pytest.raises(ValueError):
        check(data)


def test_duplicate_identity_rejected_even_with_different_version():
    data = sample()
    data["records"].append(dict(data["records"][0], version="02"))
    data["record_count"] += 1
    with pytest.raises(ValueError, match="Duplicate inventory native identity"):
        check(data)


@pytest.mark.parametrize(
    "mutation",
    ["hidden-field", "boolean", "outside-root", "count", "coverage", "duplicate-sid"],
)
def test_malformed_fields_and_scope_are_rejected(mutation):
    data = sample()
    if mutation == "hidden-field":
        data["records"][0]["UninstallString"] = "do-not-execute"
    elif mutation == "boolean":
        data["records"][1]["is_framework"] = 0
    elif mutation == "outside-root":
        data["records"][0]["native_id"] = r"HKEY_USERS\Unrelated\App"
    elif mutation == "count":
        data["record_count"] = 0
    elif mutation == "coverage":
        data["coverage"]["unloaded_user_hives"] = "complete"
    else:
        data["records"][1]["user_states"] *= 2
    with pytest.raises(ValueError):
        check(data)


def test_complete_empty_collection_and_missing_names_remain_visible():
    data = sample()
    data["records"][0]["name"] = None
    assert check(data)["records"][0]["name"] is None
    data["records"] = []
    data["record_count"] = 0
    assert check(data)["records"] == []


def test_truncated_output_duplicate_json_keys_and_nonfinite_values_rejected():
    raw = json.dumps(sample()).encode()
    for invalid in (
        raw[:-2],
        raw.replace(b'"complete": true', b'"complete": true, "complete": true'),
        raw.replace(b'"system_component": 0', b'"system_component": NaN'),
    ):
        with pytest.raises(ValueError):
            validate(invalid, BINDING)


@pytest.mark.parametrize("sid", ["S-1-5-21-1-2-3-1000", "S-1-12-1-11-22-33-44"])
def test_loaded_hives_are_explicit_and_not_silently_expanded(sid):
    data = deepcopy(sample())
    data["coverage"]["loaded_user_sids"] = [sid]
    with pytest.raises(ValueError, match="coverage differs"):
        check(data)
    data["coverage"]["registry_roots"] += [
        "Registry::HKEY_USERS\\" + sid + suffix for suffix in REGISTRY_SUFFIXES
    ]
    assert check(data) == data


@pytest.mark.parametrize(
    "invalid_sid",
    [
        "Microsoft.Windows.Appx.PackageManager.Commands.AppxUserSecurityId",
        "",
        "S-1-5-21-not-a-sid",
    ],
)
def test_appx_type_name_or_malformed_identity_is_never_an_account_sid(invalid_sid):
    value = sample()
    value["records"][1]["user_states"][0]["sid"] = invalid_sid
    with pytest.raises(ValueError):
        check(value)


@pytest.mark.parametrize(
    "sid",
    [
        "S-1-12-1-11-22-33-44_Classes",
        "S-1-12-1-11-22-33",
        "S-1-12-1-11-22-33-44-55",
        "S-1-5-18",
        ".DEFAULT",
        "S-1-12-1-11-22-33-44\\Other",
        "S-1-12-1-11-22-33-٤٤",
    ],
)
def test_loaded_hive_filter_excludes_non_account_and_malformed_roots(sid):
    data = sample()
    data["coverage"]["loaded_user_sids"] = [sid]
    data["coverage"]["registry_roots"] += [
        "Registry::HKEY_USERS\\" + sid + suffix for suffix in REGISTRY_SUFFIXES
    ]
    with pytest.raises(ValueError, match="Invalid loaded-user SID"):
        check(data)


def test_entra_user_registry_observation_requires_its_declared_loaded_hive():
    data = sample()
    sid = "S-1-12-1-11-22-33-44"
    data["records"][0]["native_id"] = (
        "HKEY_USERS\\" + sid + REGISTRY_SUFFIXES[0] + "\\SyntheticApp"
    )
    with pytest.raises(ValueError, match="outside declared roots"):
        check(data)
    data["coverage"]["loaded_user_sids"] = [sid]
    data["coverage"]["registry_roots"] += [
        "Registry::HKEY_USERS\\" + sid + suffix for suffix in REGISTRY_SUFFIXES
    ]
    assert check(data)["records"][0]["native_id"].startswith("HKEY_USERS\\" + sid)


@pytest.mark.parametrize("bundle", [True, False])
def test_explicit_bundle_flag_is_preserved(bundle):
    value = sample()
    value["records"][1]["is_bundle"] = bundle
    assert check(value)["records"][1]["is_bundle"] is bundle


def test_old_inventory_does_not_fabricate_bundle_status():
    assert "is_bundle" not in check(sample())["records"][1]


@pytest.mark.parametrize("bundle", [None, 0, 1, "false", "true", [], {}])
def test_bundle_flag_must_be_an_explicit_boolean(bundle):
    value = sample()
    value["records"][1]["is_bundle"] = bundle
    with pytest.raises(ValueError, match="Invalid Appx boolean"):
        check(value)


def test_registry_entries_cannot_acquire_appx_bundle_flags():
    value = sample()
    value["records"][0]["is_bundle"] = False
    with pytest.raises(ValueError, match="Unexpected inventory observation fields"):
        check(value)


def test_empty_registry_key_is_preserved_without_inventing_a_product():
    value = sample()
    record = value["records"][0]
    for key in ("name", "version", "system_component"):
        record[key] = None
    record.update(reported_value_names=[], localized_name=None)
    assert check(value)["records"][0] == record


def test_localized_registry_reference_is_preserved_without_dereferencing():
    value = sample()
    record = value["records"][0]
    record.update(
        reported_value_names=[
            "DisplayName",
            "DisplayVersion",
            "SystemComponent",
            "DisplayName_Localized",
        ],
        localized_name="@C:\\Synthetic\\synthetic.exe,-123",
    )
    assert check(value)["records"][0] == record


@pytest.mark.parametrize(
    "names", [None, "DisplayName", [None], [1], ["Publisher", "publisher"], []]
)
def test_registry_value_presence_rejects_invalid_or_conflicting_evidence(names):
    value = sample()
    value["records"][0]["reported_value_names"] = names
    with pytest.raises(ValueError):
        check(value)


def test_appx_cannot_acquire_registry_metadata():
    value = sample()
    value["records"][1]["reported_value_names"] = []
    with pytest.raises(ValueError, match="Unexpected inventory observation fields"):
        check(value)


def test_old_registry_observation_does_not_invent_value_presence():
    assert "reported_value_names" not in check(sample())["records"][0]
