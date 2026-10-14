"""Exact package recognition preserves source identities and applicability unknowns."""

from backend.database import schema as database_schema

import json
from pathlib import Path

import pytest

from .test_store import db as db


REFERENCE = json.loads(
    (
        Path(__file__).resolve().parents[2]
        / "backend/database/baseline/references/windows_media_identities.json"
    ).read_text()
)
PUBLISHER = (
    "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
)


def facts(name="Microsoft.AV1VideoExtension", **changes):
    return (
        dict(
            source="Windows inventory",
            kind="appx",
            native_id="synthetic-opaque-identity",
            name=name,
            product=name,
            publisher=PUBLISHER,
            family_name=name + "_8wekyb3d8bbwe",
            version="1.2.3.4",
            platform="windows",
            operating_system="Windows11",
            is_framework=False,
            is_resource_package=False,
            user_states=[dict(install_state="Installed")],
        )
        | changes
    )


@pytest.fixture
def recognize(db):
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute("SET LOCAL ROLE tm_mock_reader")

        def call(value):
            cur.execute(
                "SELECT evidence_pipeline.recognize_windows_inventory(%s::jsonb)",
                (json.dumps(value),),
            )
            return cur.fetchone()[0]

        yield call


@pytest.mark.parametrize("entry", REFERENCE["packages"], ids=lambda item: item["name"])
def test_published_installed_identity_is_not_an_advisory_alias(recognize, entry):
    original = facts(entry["name"])
    result = recognize(original)
    assert result["state"] == "recognized"
    assert result["family"] == entry["family"]
    assert result["profile"] == REFERENCE["profile"]
    assert result["identity_reference_url"] == REFERENCE["source_url"]
    assert result["identity_reference_sha256"] == REFERENCE["source_sha256"]
    assert result["inventory"] == original
    assert result["reported_version"] == "1.2.3.4"
    assert result["applicability"] == "unknown"
    assert result["distribution"] == "windows_package"


@pytest.mark.parametrize(
    "changes,reason",
    [
        (
            {"publisher": "Unrelated Publisher"},
            "unsupported_inventory_product_identity",
        ),
        ({"source": "Intune"}, "unsupported_inventory_product_identity"),
        (
            {"product": "Microsoft.AV1VideoExtensionBeta"},
            "unsupported_inventory_product_identity",
        ),
        (
            {"family_name": "Microsoft.AV1VideoExtension_otherpublisher"},
            "conflicting_published_package_family",
        ),
        ({"family_name": None}, "conflicting_published_package_family"),
        ({"is_framework": True}, "conflicting_application_package_kind"),
        ({"is_framework": None}, "conflicting_application_package_kind"),
        ({"is_resource_package": True}, "unsupported_inventory_installation_evidence"),
        ({"is_resource_package": None}, "unsupported_inventory_installation_evidence"),
        ({"kind": "registry"}, "unsupported_inventory_installation_evidence"),
        ({"native_id": ""}, "unsupported_inventory_installation_evidence"),
        (
            {"user_states": [{"install_state": "Staged"}]},
            "unsupported_inventory_installation_evidence",
        ),
        ({"user_states": []}, "unsupported_inventory_installation_evidence"),
        ({"platform": "linux"}, "missing_or_conflicting_inventory_platform"),
        ({"operating_system": None}, "missing_or_conflicting_inventory_platform"),
    ],
)
def test_missing_conflicting_or_uninstalled_package_remains_unknown(
    recognize, changes, reason
):
    original = facts(**changes)
    result = recognize(original)
    assert result["state"] == "unknown"
    assert result["family"] is None
    assert result["reason"] == reason
    assert result["applicability"] == "unknown"
    assert result["inventory"] == original


def test_no_prefix_or_opaque_identity_parsing(recognize):
    original = facts(
        "Microsoft.SyntheticUnlistedApp",
        native_id="Microsoft.AV1VideoExtension_1.2.3.4_x64__8wekyb3d8bbwe",
    )
    assert recognize(original)["state"] == "unknown"


def test_multiple_users_and_versions_are_not_coalesced(recognize):
    original = facts(
        user_states=[{"install_state": "Installed"}, {"install_state": "Staged"}]
    )
    first = recognize(original)
    second = recognize(
        original | {"version": "3001.2.3.4", "native_id": "another-synthetic-identity"}
    )
    assert first["state"] == second["state"] == "recognized"
    assert first["reported_version"] != second["reported_version"]
    assert first["inventory"] == original


def test_upgrade_is_idempotent_and_checks_drift(db):
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute(
            "GRANT EXECUTE ON FUNCTION evidence_pipeline.recognize_windows_inventory(jsonb) TO PUBLIC"
        )
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cur)


def test_published_reference_metadata_is_part_of_upgrade_identity(db):
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute(
            "UPDATE evidence_pipeline.installation SET artifacts=artifacts-'references/windows_media_identities.json' WHERE singleton"
        )
        with pytest.raises(ValueError, match="metadata differs"):
            database_schema.verify(cur)


@pytest.mark.parametrize(
    "name",
    [
        "Microsoft.HEVCVideoExtensions",
        "Microsoft.AV1VideoExtensionBeta",
        "DolbyLaboratories.DolbyVisionAccess",
    ],
)
def test_unobserved_or_similar_family_is_not_added(recognize, name):
    assert recognize(facts(name))["state"] == "unknown"


def test_missing_version_still_preserves_identity_without_applicability(recognize):
    original = facts(version=None)
    result = recognize(original)
    assert result["state"] == "recognized"
    assert result["reported_version_parts"] is None
    assert result["applicability"] == "unknown"
    assert result["inventory"] == original
