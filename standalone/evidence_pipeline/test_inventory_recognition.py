"""Generated inventory facts distinguish recognition from applicability."""

from backend.database import schema as database_schema

import json

import pytest

from .test_store import db as db


PACKAGE_PUBLISHER = (
    "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
)
PROFILES = [
    ("MSTeams", PACKAGE_PUBLISHER, "Microsoft Teams"),
    ("Microsoft Edge", "Microsoft Corporation", "Microsoft Edge"),
    (
        "Microsoft Intune Management Extension",
        "Microsoft Corporation",
        "Microsoft Intune Management Extension",
    ),
    ("Microsoft OneDrive", "Microsoft Corporation", "Microsoft OneDrive"),
    (
        "Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.42.12345",
        "Microsoft Corporation",
        "Microsoft Visual C++ 2015-2022 Redistributable",
    ),
    (
        "Microsoft Visual C++ 2015-2022 Redistributable (x86) - 14.42.12345",
        "Microsoft Corporation",
        "Microsoft Visual C++ 2015-2022 Redistributable",
    ),
    ("Microsoft.MicrosoftEdge.Stable", PACKAGE_PUBLISHER, "Microsoft Edge"),
    ("Microsoft.OutlookForWindows", PACKAGE_PUBLISHER, "Outlook for Windows"),
    ("Microsoft.Windows.DevHome", PACKAGE_PUBLISHER, "Windows Dev Home"),
    ("Microsoft.WindowsAppRuntime.1.5", PACKAGE_PUBLISHER, "Windows App Runtime 1.5"),
    ("Microsoft.WindowsAppRuntime.1.6", PACKAGE_PUBLISHER, "Windows App Runtime 1.6"),
    ("MicrosoftCorporationII.QuickAssist", PACKAGE_PUBLISHER, "Microsoft Quick Assist"),
    ("OpenSSH", "Microsoft Corporation", "Microsoft OpenSSH for Windows"),
    ("VMware Tools", "Broadcom Inc.", "VMware Tools"),
]


@pytest.fixture
def recognize(db):
    with db.cursor() as cursor:
        database_schema.verify(cursor)
        cursor.execute("SET LOCAL ROLE tm_mock_reader")

        def evaluate(facts):
            cursor.execute(
                "SELECT evidence_pipeline.recognize_windows_inventory(%s::jsonb)",
                (json.dumps(facts),),
            )
            return cursor.fetchone()[0]

        yield evaluate


def test_recognition_upgrade_preserves_previous_verifiers_and_reader(db):

    with db.cursor() as cursor:
        database_schema.verify(cursor)
        cursor.execute("SET LOCAL ROLE tm_mock_reader")
        cursor.execute(
            "SELECT recognition FROM evidence_pipeline.current_inventory_identities LIMIT 0"
        )
        assert cursor.description[0].name == "recognition"
        cursor.execute("RESET ROLE")
        cursor.execute(
            "GRANT EXECUTE ON FUNCTION evidence_pipeline.recognize_windows_inventory(jsonb) TO PUBLIC"
        )
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cursor)


@pytest.mark.parametrize("product,publisher,family", PROFILES)
def test_exact_inventory_profiles_preserve_source_values(
    recognize, product, publisher, family
):
    facts = dict(
        source="Intune",
        product=product,
        publisher=publisher,
        platform="windows",
        operating_system="Windows11",
        version="2099.02.003.4",
    )
    result = recognize(facts)
    assert result["state"] == "recognized" and result["family"] == family
    assert result["inventory"] == facts
    assert result["reported_version"] == "2099.02.003.4"
    assert result["reported_version_parts"] == ["2099", "02", "003", "4"]
    assert result["applicability"] == "unknown"
    assert result["distribution"] == (
        "windows_package" if publisher == PACKAGE_PUBLISHER else "desktop_application"
    )
    assert result["architecture"] == (
        "x64" if "(x64)" in product else "x86" if "(x86)" in product else None
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("source", "Defender"),
        ("publisher", "Microsoft"),
        ("product", "Microsoft Edge Beta"),
        ("product", "Microsoft Edge "),
        ("product", "Microsoft Edge WebView2 Runtime Beta"),
        ("platform", "linux"),
        ("operating_system", "Windows or Linux"),
        ("operating_system", None),
        ("publisher", PACKAGE_PUBLISHER),
    ],
)
def test_ambiguous_or_conflicting_input_does_not_match(recognize, field, value):
    facts = dict(
        source="Intune",
        product="Microsoft Edge",
        publisher="Microsoft Corporation",
        platform="windows",
        operating_system="Windows",
        version="2099.1.2.3",
    )
    facts[field] = value
    result = recognize(facts)
    assert result["state"] == "unknown" and result["family"] is None
    assert result["inventory"] == facts and result["applicability"] == "unknown"


@pytest.mark.parametrize(
    "version", [None, "unknown", "1.2-beta", "1", "999999999999.1", [1, 2]]
)
def test_identity_never_invents_version_mapping(recognize, version):
    facts = dict(
        source="Intune",
        product="OpenSSH",
        publisher="Microsoft Corporation",
        platform="windows",
        operating_system="Windows",
        version=version,
    )
    result = recognize(facts)
    assert result["state"] == "recognized"
    assert result["reported_version"] == version
    assert result["reported_version_parts"] is None
    assert result["applicability"] == "unknown"
