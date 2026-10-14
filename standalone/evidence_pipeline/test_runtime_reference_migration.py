"""Exact reference rows reach restricted SQL without broadening applicability."""

from backend.database import schema as database_schema

import json
from pathlib import Path

import pytest

from .test_store import db as db

REFERENCE = json.loads(
    (
        Path(__file__).resolve().parents[2]
        / "backend/database/baseline/references/windows_runtime_releases.json"
    ).read_text()
)
PUBLISHER = (
    "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
)


def facts(row, source="Windows inventory"):
    return dict(
        source=source,
        product=row["product"],
        version=row["msix_version"],
        publisher=PUBLISHER,
        kind="appx",
        native_id="synthetic-package-id",
        family_name=row["product"] + "_8wekyb3d8bbwe",
        is_framework=True,
        is_resource_package=False,
        user_states=[dict(install_state="Installed")],
        platform="windows",
        operating_system="Windows11",
    )


@pytest.fixture
def evaluate(db):
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute("SET LOCAL ROLE tm_mock_reader")

        def call(value):
            cur.execute(
                "SELECT evidence_pipeline.windows_runtime_release(%s::jsonb)",
                (json.dumps(value),),
            )
            return cur.fetchone()[0]

        yield call


@pytest.mark.parametrize("row", REFERENCE["mappings"], ids=lambda r: r["sdk_release"])
@pytest.mark.parametrize("source", ["Intune", "Windows inventory"])
def test_all_reference_rows_preserve_exact_original_versions(evaluate, row, source):
    original = facts(row, source)
    result = evaluate(original)
    assert result["state"] == "matched"
    assert result["sdk_release"] == row["sdk_release"]
    assert result["nuget_version"] == row["nuget_version"]
    assert result["reported_msix_version"] == row["msix_version"]
    assert result["inventory"] == original
    assert result["applicability"] == "unknown"
    assert result["source_url"] == REFERENCE["source_url"]
    assert result["source_markdown_sha256"] == REFERENCE["source_markdown_sha256"]


@pytest.mark.parametrize(
    "changes",
    [
        dict(family_name=None),
        dict(family_name="Microsoft.WindowsAppRuntime.2_otherpublisher"),
        dict(is_framework=False),
        dict(is_framework=None),
        dict(is_resource_package=True),
        dict(user_states=[]),
        dict(user_states=[dict(install_state="Staged")]),
        dict(native_id=""),
        dict(kind="registry"),
        dict(source="Defender"),
        dict(publisher="Microsoft Corporation"),
        dict(platform="linux"),
        dict(operating_system=None),
        dict(version="7000.785.2325"),
        dict(version="1.7.9"),
        dict(version="7000.785.2325.1"),
        dict(product="Microsoft.WindowsAppRuntime.1.70"),
        dict(product="Microsoft.WindowsAppRuntime.CBS.1.7"),
    ],
)
def test_conflicting_identity_or_neighbouring_versions_remain_unknown(
    evaluate, changes
):
    row = next(r for r in REFERENCE["mappings"] if r["sdk_release"] == "1.7.9")
    original = facts(row) | changes
    result = evaluate(original)
    assert result["state"] == "unknown"
    assert result["sdk_release"] is None and result["nuget_version"] is None
    assert result["applicability"] == "unknown" and result["inventory"] == original


def test_reference_has_unique_exact_keys_and_installed_artifact_binding(db):
    rows = REFERENCE["mappings"]
    assert len(rows) == len({(r["product"], r["msix_version"]) for r in rows})
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute(
            "UPDATE evidence_pipeline.installation SET artifacts=artifacts-'references/windows_runtime_releases.json' WHERE singleton"
        )
        with pytest.raises(ValueError, match="metadata differs"):
            database_schema.verify(cur)


def test_new_view_cannot_be_publicly_granted_without_drift_detection(db):
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute(
            "GRANT SELECT ON evidence_pipeline.current_native_runtime_releases TO PUBLIC"
        )
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cur)
