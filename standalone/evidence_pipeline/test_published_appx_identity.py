"""Published Appx identity contracts; preserve profile-specific installation facts."""

import json
from pathlib import Path

import pytest

from backend.database import schema as database_schema
from .test_store import db as db

# Defaults deliberately retain absent is_bundle fields where the original source
# contract allowed them. Native framework/system observations require False.
PROFILES = {
    "store": ("windows_store_identities.json", "Microsoft.HEIFImageExtension", False),
    "framework": ("windows_framework_identities.json", "Microsoft.UI.Xaml.2.8", True),
    "store_extension": (
        "windows_store_extension_identities.json",
        "Microsoft.HEIFImageExtension",
        False,
    ),
    "store_system": (
        "windows_store_system_identities.json",
        "Microsoft.ApplicationCompatibilityEnhancements",
        False,
    ),
    "native_framework": (
        "windows_native_framework_identities.json",
        "Microsoft.NET.Native.Framework.2.2",
        True,
    ),
    "system_component": (
        "windows_system_component_extensions.json",
        "Microsoft.Windows.StartMenuExperienceHost",
        False,
    ),
}
REFERENCES = {
    family: json.loads(
        (
            Path(__file__).resolve().parents[2]
            / "backend/database/baseline/references"
            / spec[0]
        ).read_text()
    )
    for family, spec in PROFILES.items()
}
EXPECTED_PROFILES = {
    "store_system": "native-windows-store-identities-v1",
    "native_framework": "native-windows-framework-identities-v1",
    "system_component": "native-windows-system-identities-v1",
}


def facts(family, name=None, **changes):
    _, default_name, framework = PROFILES[family]
    name = default_name if name is None else name
    system = family == "system_component"
    return (
        dict(
            source="Windows inventory",
            kind="appx",
            native_id="synthetic-opaque-identity",
            name=name,
            product=name,
            publisher=("CN=Microsoft Windows" if system else "CN=Microsoft Corporation")
            + ", O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
            family_name=name + ("_cw5n1h2txyewy" if system else "_8wekyb3d8bbwe"),
            version="1.2.3.4",
            platform="windows",
            operating_system="Windows11",
            is_framework=framework,
            is_resource_package=False,
            user_states=[dict(install_state="Installed")],
        )
        | (
            {"is_bundle": False}
            if family in {"native_framework", "system_component"}
            else {}
        )
        | changes
    )


def published_facts(family, entry, **changes):
    if family in {"store_extension", "store_system"}:
        changes = (
            dict(publisher=entry["publisher"], family_name=entry["package_family"])
            | changes
        )
    return facts(family, entry["name"], **changes)


def negative_cases(family):
    _, name, framework = PROFILES[family]
    kind = (
        "system"
        if family == "system_component"
        else "framework"
        if framework
        else "application"
    )
    identity = "unsupported_inventory_product_identity"
    installation = "unsupported_inventory_installation_evidence"
    platform = "missing_or_conflicting_inventory_platform"
    cases = [
        ({"publisher": "Unrelated Publisher"}, identity),
        ({"source": "Intune"}, identity),
        ({"product": name + "Beta"}, identity),
        (
            {"family_name": name + "_otherpublisher"},
            "conflicting_published_package_family",
        ),
        ({"family_name": None}, "conflicting_published_package_family"),
        ({"is_framework": not framework}, f"conflicting_{kind}_package_kind"),
        ({"is_framework": None}, f"conflicting_{kind}_package_kind"),
    ]
    if family in {"native_framework", "system_component"}:
        cases += [
            ({"is_bundle": value}, f"conflicting_{kind}_package_kind")
            for value in (True, None)
        ]
    return cases + [
        ({"is_resource_package": True}, installation),
        ({"is_resource_package": None}, installation),
        ({"kind": "registry"}, installation),
        ({"native_id": ""}, installation),
        ({"user_states": [{"install_state": "Staged"}]}, installation),
        ({"user_states": []}, installation),
        ({"platform": "linux"}, platform),
        ({"operating_system": None}, platform),
    ]


def unlisted_names(family):
    store = family in {"store", "store_extension", "store_system"}
    return [
        "Microsoft.HEVCVideoExtensions" if store else "Microsoft.UI.Xaml.2.9",
        PROFILES[family][1] + "Beta",
        "DolbyLaboratories.DolbyVisionAccess"
        if store
        else "Microsoft.WindowsAppRuntime.CBS",
    ]


@pytest.fixture
def recognize(db):
    with db.cursor() as cursor:
        database_schema.verify(cursor)
        cursor.execute("SET LOCAL ROLE tm_mock_reader")

        def call(value):
            cursor.execute(
                "SELECT evidence_pipeline.recognize_windows_inventory(%s::jsonb)",
                (json.dumps(value),),
            )
            return cursor.fetchone()[0]

        yield call


@pytest.mark.parametrize(
    "family,entry,changes",
    [
        pytest.param(family, entry, changes, id=f"{family}-{entry['name']}-{changes}")
        for family, reference in REFERENCES.items()
        for entry in reference["packages"]
        for changes in (
            [{"is_bundle": False}, {"is_bundle": True}]
            if family == "store_system"
            else [{}]
        )
    ],
)
def test_published_installed_identity_is_not_an_advisory_alias(
    recognize, family, entry, changes
):
    original = published_facts(family, entry, **changes)
    result = recognize(original)
    assert result["state"] == "recognized"
    assert result["family"] == entry["family"]
    assert result["profile"] == (
        EXPECTED_PROFILES[family]
        if family in EXPECTED_PROFILES
        else REFERENCES[family]["profile"]
    )
    assert result["identity_reference_url"] == entry["source_url"]
    assert result["identity_reference_sha256"] == entry["source_sha256"]
    assert result["inventory"] == original
    assert result["reported_version"] == "1.2.3.4"
    assert result["applicability"] == "unknown"
    assert result["distribution"] == "windows_package"


@pytest.mark.parametrize(
    "family,name,changes,reason",
    [
        pytest.param(family, name, changes, reason, id=f"{family}-{name}-{index}")
        for family in PROFILES
        for name in (
            [entry["name"] for entry in REFERENCES[family]["packages"]]
            if family == "native_framework"
            else [PROFILES[family][1]]
        )
        for index, (changes, reason) in enumerate(negative_cases(family))
    ],
)
def test_missing_conflicting_or_uninstalled_package_remains_unknown(
    recognize, family, name, changes, reason
):
    original = facts(family, name, **changes)
    result = recognize(original)
    assert result["state"] == "unknown"
    assert result["family"] is None
    assert result["reason"] == reason
    assert result["applicability"] == "unknown"
    assert result["inventory"] == original


@pytest.mark.parametrize("family", PROFILES)
def test_no_prefix_or_opaque_identity_parsing(recognize, family):
    suffix = "cw5n1h2txyewy" if family == "system_component" else "8wekyb3d8bbwe"
    original = facts(
        family,
        "Microsoft.SyntheticUnlistedApp",
        native_id=PROFILES[family][1] + "_1.2.3.4_x64__" + suffix,
    )
    assert recognize(original)["state"] == "unknown"


@pytest.mark.parametrize("family", PROFILES)
def test_multiple_users_and_versions_are_not_coalesced(recognize, family):
    original = facts(
        family,
        user_states=[{"install_state": "Installed"}, {"install_state": "Staged"}],
    )
    changed = original | {
        "version": "3001.2.3.4",
        "native_id": "another-synthetic-identity",
    }
    first, second = recognize(original), recognize(changed)
    assert first["state"] == second["state"] == "recognized"
    assert first["reported_version"] != second["reported_version"]
    assert first["inventory"] == original
    assert second["inventory"] == changed


@pytest.mark.parametrize("family", PROFILES)
def test_each_reference_artifact_is_required_by_current_installation(db, family):
    artifact = "references/" + PROFILES[family][0]
    with db.cursor() as cursor:
        database_schema.verify(cursor)
        cursor.execute(
            "SELECT artifacts ? %s FROM evidence_pipeline.installation WHERE singleton",
            (artifact,),
        )
        assert cursor.fetchone() == (True,)
        cursor.execute(
            "UPDATE evidence_pipeline.installation SET artifacts=artifacts-%s WHERE singleton",
            (artifact,),
        )
        with pytest.raises(ValueError, match="metadata differs"):
            database_schema.verify(cursor)


@pytest.mark.parametrize(
    "family,name",
    [(family, name) for family in PROFILES for name in unlisted_names(family)],
)
def test_unobserved_or_similar_family_is_not_added(recognize, family, name):
    assert recognize(facts(family, name))["state"] == "unknown"


@pytest.mark.parametrize("family", PROFILES)
def test_missing_version_still_preserves_identity_without_applicability(
    recognize, family
):
    original = facts(family, version=None)
    result = recognize(original)
    assert result["state"] == "recognized"
    assert result["reported_version_parts"] is None
    assert result["applicability"] == "unknown"
    assert result["inventory"] == original


@pytest.mark.parametrize(
    "family,entry",
    [
        (family, entry)
        for family in ("store_extension", "store_system")
        for entry in REFERENCES[family]["packages"]
    ],
)
@pytest.mark.parametrize("field", ["publisher", "family_name"])
def test_each_store_identity_requires_its_exact_publisher_and_family(
    recognize, family, entry, field
):
    original = published_facts(family, entry)
    original[field] = "Synthetic conflicting identity"
    result = recognize(original)
    assert result["state"] == "unknown"
    assert result["applicability"] == "unknown"
    assert result["inventory"] == original


@pytest.mark.parametrize(
    "entry", REFERENCES["store_system"]["packages"], ids=lambda entry: entry["name"]
)
@pytest.mark.parametrize(
    "changes",
    [
        {"is_framework": True},
        {"is_resource_package": True},
        {"user_states": [{"install_state": "Staged"}]},
        {"kind": "registry"},
    ],
)
def test_each_store_system_reference_requires_supported_installation_facts(
    recognize, entry, changes
):
    original = published_facts("store_system", entry, **changes)
    result = recognize(original)
    assert result["state"] == "unknown"
    assert result["applicability"] == "unknown"
    assert result["inventory"] == original


@pytest.mark.parametrize(
    "entry", REFERENCES["native_framework"]["packages"], ids=lambda entry: entry["name"]
)
def test_reference_version_does_not_replace_observed_version(recognize, entry):
    original = facts("native_framework", entry["name"], version="9.8.7.6")
    assert original["version"] != entry["reference_package_version"]
    result = recognize(original)
    assert result["state"] == "recognized"
    assert result["reported_version"] == original["version"]
    assert (
        result["version_interpretation"]
        == "inventory_reported_version_not_an_upstream_version_mapping"
    )
    assert result["applicability"] == "unknown"
