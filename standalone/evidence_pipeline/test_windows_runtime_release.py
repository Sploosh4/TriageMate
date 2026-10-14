"""Exact publisher release mapping, without inferred patch or component status."""

from backend.database import schema as database_schema

import pytest

from .test_store import db as db

PUBLISHER = (
    "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
)


def facts():
    return dict(
        source="Intune",
        product="Microsoft.WindowsAppRuntime.1.5",
        publisher=PUBLISHER,
        version="5001.311.2039.0",
        platform="windows",
        operating_system="Windows11",
    )


def evaluate(db, value):
    import json

    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        cur.execute(
            "SELECT evidence_pipeline.windows_runtime_release(%s::jsonb)",
            (json.dumps(value),),
        )
        return cur.fetchone()[0]


@pytest.mark.parametrize(
    "product,version,release,nuget",
    [
        (
            "Microsoft.WindowsAppRuntime.1.5",
            "5001.311.2039.0",
            "1.5.8",
            "1.5.241107002",
        ),
        (
            "Microsoft.WindowsAppRuntime.1.6",
            "6000.401.2352.0",
            "1.6.5",
            "1.6.250205002",
        ),
    ],
)
def test_exact_publisher_release_preserves_original_and_unknown_applicability(
    db, product, version, release, nuget
):
    value = {**facts(), "product": product, "version": version}
    result = evaluate(db, value)
    assert result["state"] == "matched"
    assert result["sdk_release"] == release and result["nuget_version"] == nuget
    assert result["reported_msix_version"] == version and result["inventory"] == value
    assert result["applicability"] == "unknown"
    assert result["source_url"].endswith("/1e6bada959624bd587c8a9e62e2dbcdd1cc24297")


@pytest.mark.parametrize(
    "changes",
    [
        {"source": "Defender"},
        {"publisher": "Microsoft Corporation"},
        {"platform": "linux"},
        {"operating_system": "Linux"},
        {"operating_system": None},
        {"product": "Microsoft.WindowsAppRuntime.1.6"},
        {"product": "Microsoft.WindowsAppRuntime.1.50"},
        {"version": "5001.311.2039"},
        {"version": "5001.311.2039.1"},
        {"version": "1.5.8"},
        {"version": None},
    ],
)
def test_unproven_identities_and_neighbouring_versions_stay_unknown(db, changes):
    result = evaluate(db, {**facts(), **changes})
    assert result["state"] == "unknown" and result["sdk_release"] is None
    assert result["nuget_version"] is None and result["applicability"] == "unknown"


@pytest.mark.parametrize("value", [None, [], True, "unknown"])
def test_malformed_facts_do_not_invent_identity(db, value):
    assert evaluate(db, value)["state"] == "unknown"


def test_upgrade_idempotence_and_reader_authority_drift(db):

    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute(
            "GRANT EXECUTE ON FUNCTION evidence_pipeline.windows_runtime_release(jsonb) TO PUBLIC"
        )
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cur)
