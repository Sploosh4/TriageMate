"""Exact published component identities preserve versions and unknown applicability."""

import json
import pytest
from backend.database import schema as database_schema
from backend.tests.windows_identity_support import PROFILES, REFERENCES, facts
from .test_store import db as db

CASES = [
    pytest.param(family, entry, id=f"{family}-{entry['name']}")
    for family, reference in REFERENCES.items()
    for entry in reference["packages"]
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


@pytest.mark.parametrize("family,entry", CASES)
def test_exact_published_identity_keeps_version_and_applicability_separate(
    recognize, family, entry
):
    original = facts(entry, family=family)
    result = recognize(original)
    assert result["state"] == "recognized"
    assert result["family"] == entry["family"]
    assert result["profile"] == PROFILES[family][1]
    assert result["identity_reference_url"] == entry["source_url"]
    assert result["identity_reference_sha256"] == entry["source_sha256"]
    assert result["inventory"] == original
    assert result["reported_version"] == "1.2.3.4"
    assert (
        result["version_interpretation"]
        == "inventory_reported_version_not_an_upstream_version_mapping"
    )
    assert result["applicability"] == "unknown"


@pytest.mark.parametrize("family,entry", CASES)
@pytest.mark.parametrize(
    "changes",
    [
        {"publisher": "Synthetic unrelated publisher"},
        {"publisher": None},
        {"source": "Intune"},
        {"kind": "registry"},
        {"native_id": ""},
        {"product": "Microsoft.SyntheticCBS"},
        {"family_name": "Synthetic_wrong_family"},
        {"family_name": None},
        {"is_framework": None},
        {"is_bundle": True},
        {"is_bundle": None},
        {"is_resource_package": True},
        {"is_resource_package": None},
        {"user_states": []},
        {"user_states": [{"install_state": "Staged"}]},
        {"platform": "linux"},
        {"operating_system": None},
    ],
)
def test_missing_conflicting_or_uninstalled_evidence_stays_unknown(
    recognize, family, entry, changes
):
    original = facts(entry, family=family, **changes)
    result = recognize(original)
    assert result["state"] == "unknown"
    assert result["family"] is None
    assert result["applicability"] == "unknown"
    assert result["inventory"] == original


@pytest.mark.parametrize("family,entry", CASES)
def test_opposite_framework_kind_and_similar_names_are_not_aliases(
    recognize, family, entry
):
    assert (
        recognize(facts(entry, family=family, is_framework=not entry["is_framework"]))[
            "state"
        ]
        == "unknown"
    )
    assert (
        recognize(
            facts(entry, family=family, product=entry["name"] + ".SyntheticSuffix")
        )["state"]
        == "unknown"
    )


@pytest.mark.parametrize("family,entry", CASES)
@pytest.mark.parametrize("version", [None, "opaque-version", "26100.1234.5.6"])
def test_missing_or_unmapped_version_does_not_invent_a_servicing_version(
    recognize, family, entry, version
):
    original = facts(entry, family=family, version=version)
    result = recognize(original)
    assert result["state"] == "recognized"
    assert result["reported_version"] == version
    assert result["applicability"] == "unknown"
    assert result["inventory"] == original
    if version in (None, "opaque-version"):
        assert result["reported_version_parts"] is None


def test_recognizer_rejects_authority_drift(db):
    with db.cursor() as cursor:
        database_schema.verify(cursor)
        cursor.execute(
            "GRANT EXECUTE ON FUNCTION evidence_pipeline.recognize_windows_inventory(jsonb) TO PUBLIC"
        )
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cursor)


@pytest.mark.parametrize("family", PROFILES)
def test_reference_artifact_is_required(db, family):
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


ALIASES = {
    "cloud": [
        "Windows",
        "Windows 11",
        "Microsoft.CloudExperienceHost",
        "Microsoft account",
    ],
    "inbox": ["Windows", "Windows 11", "Control Panel", "Microsoft Edge"],
    "security-app": [
        "Microsoft.Windows.SecHealthUI",
        "Windows Security platform",
        "Microsoft Defender Antivirus",
        "SecurityHealthService",
    ],
}


@pytest.mark.parametrize(
    "family,entry,name",
    [
        pytest.param(family, entry, name, id=f"{family}-{entry['name']}-{name}")
        for family, names in ALIASES.items()
        for entry in REFERENCES[family]["packages"]
        for name in names
    ],
)
def test_related_os_service_and_legacy_names_are_not_aliases(
    recognize, family, entry, name
):
    result = recognize(facts(entry, family=family, product=name))
    assert result["state"] == "unknown"
    assert result["applicability"] == "unknown"


def test_unknown_framework_does_not_match_from_microsoft_publisher_alone(recognize):
    for name in (
        "Microsoft.WindowsAppRuntime.CBS",
        "Microsoft.WindowsAppRuntime.CBS.1.6",
        "Microsoft.AIFabric.CBS.1.6",
        "Microsoft.Windows.AugLoop.CBS",
    ):
        assert (
            recognize(
                facts(
                    REFERENCES["cbs"]["packages"][0],
                    name=name,
                    product=name,
                    family_name=name + "_8wekyb3d8bbwe",
                )
            )["state"]
            == "unknown"
        )


def test_app_version_is_not_converted_to_platform_version(recognize):
    original = facts(
        REFERENCES["security-app"]["packages"][0],
        family="security-app",
        version="1000.27840.0.1000",
    )
    result = recognize(original)
    assert result["reported_version"] == "1000.27840.0.1000"
    assert result["reported_version_parts"] == ["1000", "27840", "0", "1000"]
    assert result["applicability"] == "unknown"
