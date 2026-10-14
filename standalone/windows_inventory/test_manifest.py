"""Synthetic source metadata never creates a product alias or an invented name."""

from copy import deepcopy
import pytest
from .test_contract import sample, check


def metadata(**changes):
    record = sample()["records"][1]
    return (
        dict(
            state="read",
            reason="exact_manifest_package_identity",
            sha256="a" * 64,
            name=record["name"],
            version=record["version"],
            publisher=record["publisher"],
            display_name_reference="Synthetic app",
            display_name="Synthetic app",
            publisher_display_name="Synthetic publisher",
            display_name_basis="literal_manifest_value",
            signature_kind="Synthetic",
            resource_lookup_hresult=None,
            resolution_culture="en-US",
        )
        | changes
    )


def document(**changes):
    value = sample()
    value["records"][1].update(is_bundle=False, manifest=metadata(**changes))
    return value


def test_exact_literal_metadata_is_preserved_without_product_substitution():
    value = document()
    assert check(value) == value
    assert value["records"][1]["name"] == "Synthetic app"


def test_resolved_package_resource_keeps_original_reference_and_source_name():
    value = document(
        display_name_reference="ms-resource:AppStoreName",
        display_name="Synthetic friendly name",
        display_name_basis="package_resource_text",
        resource_lookup_hresult=0,
    )
    assert check(value) == value
    assert check(value)["records"][1]["name"] == "Synthetic app"


@pytest.mark.parametrize(
    "change",
    [
        {"name": "other"},
        {"publisher": "other"},
        {"version": "9.9.9.9"},
        {"sha256": "bad"},
        {"sha256": None},
        {"state": "complete"},
        {"reason": "assumed"},
        {"signature_kind": None},
        {"resolution_culture": None},
        {"resource_lookup_hresult": False},
        {"resource_lookup_hresult": 2**31},
        {"resource_lookup_hresult": -(2**31) - 1},
        {"display_name": "different"},
        {"display_name_basis": "guessed"},
        {"display_name_basis": "unresolved"},
        {
            "display_name_reference": "@arbitrary.exe,-1",
            "display_name": "@arbitrary.exe,-1",
        },
        {
            "display_name_reference": "ms-resource:Name",
            "display_name": "ms-resource:Name",
        },
    ],
)
def test_invalid_or_conflicting_metadata_is_rejected(change):
    with pytest.raises(ValueError):
        check(document(**change))


@pytest.mark.parametrize("field", ["name", "version", "publisher"])
def test_read_state_requires_actual_identity_fields(field):
    value = document()
    value["records"][1][field] = None
    value["records"][1]["manifest"][field] = None
    with pytest.raises(ValueError):
        check(value)


@pytest.mark.parametrize("status", [None, 1, -1])
def test_resolved_resource_requires_successful_lookup(status):
    with pytest.raises(ValueError):
        check(
            document(
                display_name_reference="ms-resource:Name",
                display_name_basis="package_resource_text",
                resource_lookup_hresult=status,
            )
        )


@pytest.mark.parametrize(
    "reference",
    [
        "ms-resource://Other/Name?x=1",
        "@file.exe,-1",
        "file://private",
        "literal",
        "ms-resource:../Name",
        "ms-resource:Resources/./Name",
        "ms-resource:Name#x",
        "ms-resource:Resources/%2e%2e/Name",
        "ms-resource://user@Other/Name",
    ],
)
def test_unsupported_reference_cannot_claim_resolution(reference):
    with pytest.raises(ValueError):
        check(
            document(
                display_name_reference=reference,
                display_name_basis="package_resource_text",
                resource_lookup_hresult=0,
            )
        )


def test_failed_or_unsupported_lookup_remains_explicitly_unresolved():
    for status in (None, -1, 0):
        value = document(
            display_name_reference="ms-resource://Synthetic/Name",
            display_name=None,
            display_name_basis="unresolved",
            resource_lookup_hresult=status,
        )
        assert check(value) == value


def unavailable(state="unavailable", reason="manifest_read_failed"):
    return metadata(
        state=state,
        reason=reason,
        sha256=None,
        name=None,
        version=None,
        publisher=None,
        display_name_reference=None,
        display_name=None,
        publisher_display_name=None,
        display_name_basis="unresolved",
    )


@pytest.mark.parametrize(
    "reason", ["manifest_read_failed", "manifest_identity_conflict"]
)
def test_unavailable_metadata_retains_the_package_observation(reason):
    value = document()
    value["records"][1]["manifest"] = unavailable(reason=reason)
    assert check(value) == value
    changed = deepcopy(value)
    changed["records"][1]["manifest"]["display_name"] = "invented"
    with pytest.raises(ValueError):
        check(changed)


def test_bundle_exclusion_requires_explicit_package_kind():
    value = document()
    value["records"][1]["manifest"] = unavailable(
        "not_applicable", "bundle_or_resource_package"
    )
    with pytest.raises(ValueError):
        check(value)
    value["records"][1]["is_bundle"] = True
    assert check(value) == value


def test_registry_cannot_receive_package_manifest_metadata():
    value = sample()
    value["records"][0]["manifest"] = metadata()
    with pytest.raises(ValueError):
        check(value)


def test_legacy_package_evidence_remains_replayable_without_new_metadata():
    assert "manifest" not in check(sample())["records"][1]


@pytest.mark.parametrize(
    "reference",
    [
        "ms-resource:Resources/AppName",
        "ms-resource:Library/Resources/AppName",
        "ms-resource:/Manifest/AppName",
        "ms-resource:///Resources/AppName",
        "ms-resource://Synthetic.App/Resources/AppName",
        "MS-RESOURCE:AppName",
    ],
)
def test_hierarchical_resource_reference_preserves_evidence(reference):
    value = document(
        display_name_reference=reference,
        display_name="Synthetic app name",
        display_name_basis="package_resource_text",
        resource_lookup_hresult=0,
    )
    assert check(value) == value
