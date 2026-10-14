"""Published component identity does not imply a Windows servicing or CVE version match."""

from backend.database import schema as database_schema

import json
from pathlib import Path

import pytest


from .test_store import db as db

REFERENCE = json.loads(
    (
        Path(__file__).resolve().parents[2]
        / "backend/database/baseline/references/windows_component_references.json"
    ).read_text()
)


def facts(entry, **changes):
    return (
        dict(
            source="Windows inventory",
            kind="appx",
            native_id="synthetic-cbs-identity",
            name=entry["name"],
            product=entry["name"],
            publisher=entry["publisher"],
            family_name=entry["package_family"],
            version="1.2.3.4",
            platform="windows",
            operating_system="Windows11",
            is_framework=entry["is_framework"],
            is_bundle=False,
            is_resource_package=False,
            user_states=[dict(install_state="Installed")],
        )
        | changes
    )


def install(cursor):
    database_schema.verify(cursor)


@pytest.fixture
def recognize(db):
    with db.cursor() as cursor:
        install(cursor)
        cursor.execute("SET LOCAL ROLE tm_mock_reader")

        def call(value):
            cursor.execute(
                "SELECT evidence_pipeline.recognize_windows_inventory(%s::jsonb)",
                (json.dumps(value),),
            )
            return cursor.fetchone()[0]

        yield call


@pytest.mark.parametrize(
    "entry", REFERENCE["packages"], ids=lambda entry: entry["name"]
)
def test_exact_published_identity_keeps_version_and_applicability_separate(
    recognize, entry
):
    original = facts(entry)
    result = recognize(original)
    assert result["state"] == "recognized"
    assert result["family"] == entry["family"]
    assert result["profile"] == "native-windows-component-references-v1"
    assert result["identity_reference_url"] == entry["source_url"]
    assert result["identity_reference_sha256"] == entry["source_sha256"]
    assert result["inventory"] == original
    assert result["reported_version"] == "1.2.3.4"
    assert (
        result["version_interpretation"]
        == "inventory_reported_version_not_an_upstream_version_mapping"
    )
    assert result["applicability"] == "unknown"


@pytest.mark.parametrize(
    "entry", REFERENCE["packages"], ids=lambda entry: entry["name"]
)
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
    recognize, entry, changes
):
    original = facts(entry, **changes)
    result = recognize(original)
    assert result["state"] == "unknown"
    assert result["family"] is None
    assert result["applicability"] == "unknown"
    assert result["inventory"] == original


@pytest.mark.parametrize(
    "entry", REFERENCE["packages"], ids=lambda entry: entry["name"]
)
def test_opposite_framework_kind_and_similar_names_are_not_aliases(recognize, entry):
    assert (
        recognize(facts(entry, is_framework=not entry["is_framework"]))["state"]
        == "unknown"
    )
    assert (
        recognize(facts(entry, product=entry["name"] + ".SyntheticSuffix"))["state"]
        == "unknown"
    )


@pytest.mark.parametrize(
    "entry", REFERENCE["packages"], ids=lambda entry: entry["name"]
)
@pytest.mark.parametrize("version", [None, "opaque-version", "26100.1234.5.6"])
def test_missing_or_unmapped_version_does_not_invent_a_servicing_version(
    recognize, entry, version
):
    original = facts(entry, version=version)
    result = recognize(original)
    assert result["state"] == "recognized"
    assert result["reported_version"] == version
    assert result["applicability"] == "unknown"
    assert result["inventory"] == original
    if version in (None, "opaque-version"):
        assert result["reported_version_parts"] is None


def test_upgrade_is_idempotent_and_checks_authority_drift(db):
    with db.cursor() as cursor:
        install(cursor)
        database_schema.verify(cursor)
        cursor.execute(
            "GRANT EXECUTE ON FUNCTION evidence_pipeline.recognize_windows_inventory(jsonb) TO PUBLIC"
        )
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cursor)


def test_reference_artifact_is_required_by_migration(db):
    with db.cursor() as cursor:
        install(cursor)
        cursor.execute(
            "UPDATE evidence_pipeline.installation SET artifacts=artifacts-'references/windows_component_references.json' WHERE singleton"
        )
        with pytest.raises(ValueError, match="metadata differs"):
            database_schema.verify(cursor)
