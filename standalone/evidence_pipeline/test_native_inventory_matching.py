"""Native inventory source admission preserves unknowns and original facts."""

from backend.database import schema as database_schema

import json

import pytest

from .test_store import db as db, snapshot as snapshot


PUBLISHER = (
    "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
)


@pytest.fixture
def evaluate(db):
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute("SET LOCAL ROLE tm_mock_reader")

        def call(function, *values):
            cur.execute(
                "SELECT evidence_pipeline."
                + function
                + "("
                + ",".join(["%s::jsonb"] * len(values))
                + ")",
                tuple(json.dumps(v) for v in values),
            )
            return cur.fetchone()[0]

        yield call


def facts(**changes):
    return dict(
        source="Windows inventory",
        kind="registry",
        native_id="synthetic-registry-key",
        product="Microsoft Edge",
        publisher="Microsoft Corporation",
        version="123.0.0.0",
        platform="windows",
        operating_system="Windows11",
        **changes,
    )


def test_registry_recognition_preserves_actual_source_and_unknown_applicability(
    evaluate,
):
    original = facts()
    result = evaluate("recognize_windows_inventory", original)
    assert result["state"] == "recognized"
    assert result["inventory"] == original
    assert result["profile"] == "native-windows-inventory-identity-v1"
    assert result["applicability"] == "unknown"


@pytest.mark.parametrize(
    "change",
    [
        dict(kind="appx"),
        dict(native_id=""),
        dict(native_id=None),
        dict(source="Defender"),
        dict(publisher="Unrelated vendor"),
        dict(operating_system="Linux"),
    ],
)
def test_missing_or_conflicting_registry_identity_is_unknown(evaluate, change):
    result = evaluate("recognize_windows_inventory", facts() | change)
    assert result["state"] == "unknown"
    assert result["inventory"] == facts() | change


def package(**changes):
    return (
        facts()
        | dict(
            kind="appx",
            product="MSTeams",
            publisher=PUBLISHER,
            is_resource_package=False,
            user_states=[dict(sid="synthetic-user", install_state="Installed")],
        )
        | changes
    )


@pytest.mark.parametrize(
    "change",
    [
        dict(user_states=[]),
        dict(user_states=None),
        dict(user_states=[dict(install_state="Staged")]),
        dict(user_states=[dict(install_state="Paused")]),
        dict(is_resource_package=True),
        dict(is_resource_package=None),
        dict(kind="registry"),
    ],
)
def test_package_without_supported_installation_evidence_is_unknown(evaluate, change):
    assert (
        evaluate("recognize_windows_inventory", package(**change))["state"] == "unknown"
    )


def test_installed_package_preserves_other_user_states(evaluate):
    original = package(
        user_states=[dict(install_state="Staged"), dict(install_state="Installed")]
    )
    result = evaluate("recognize_windows_inventory", original)
    assert result["state"] == "recognized"
    assert result["inventory"] == original
    assert result["applicability"] == "unknown"


def test_unmapped_product_keeps_source_identity(evaluate):
    original = package(product="Synthetic.UnmappedApp")
    result = evaluate("recognize_windows_inventory", original)
    assert result["state"] == "unknown" and result["family"] is None
    assert result["inventory"] == original


def test_existing_intune_contract_is_unchanged(evaluate):
    original = facts() | dict(source="Intune")
    original.pop("native_id")
    original.pop("kind")
    result = evaluate("recognize_windows_inventory", original)
    assert result["state"] == "recognized"
    assert result["profile"] == "intune-windows-inventory-identity-v1"


def test_runtime_release_mapping_is_identity_only(evaluate):
    original = package(
        product="Microsoft.WindowsAppRuntime.1.5",
        version="5001.311.2039.0",
        family_name="Microsoft.WindowsAppRuntime.1.5_8wekyb3d8bbwe",
        is_framework=True,
    )
    result = evaluate("windows_runtime_release", original)
    assert result["state"] == "matched" and result["sdk_release"] == "1.5.8"
    assert result["inventory"] == original and result["applicability"] == "unknown"
    assert (
        evaluate("windows_runtime_release", original | dict(user_states=[]))["state"]
        == "unknown"
    )


@pytest.mark.parametrize(
    "product,publisher,vendor,target,function,kind",
    [
        (
            "VMware Tools",
            "Broadcom Inc.",
            "VMware",
            "VMware Tools",
            "inventory_product_status",
            "registry",
        ),
        (
            "Microsoft Edge",
            "Microsoft Corporation",
            "Microsoft",
            "Microsoft Edge (Chromium-based)",
            "edge_inventory_status",
            "registry",
        ),
        (
            "Microsoft OneDrive",
            "Microsoft Corporation",
            "Microsoft",
            "OneDrive for Windows",
            "windows_app_inventory_status",
            "registry",
        ),
        (
            "MSTeams",
            PUBLISHER,
            "Microsoft",
            "Microsoft Teams for Desktop",
            "windows_app_inventory_status",
            "appx",
        ),
    ],
)
@pytest.mark.parametrize(
    "change,expected",
    [
        ("supported", "affected"),
        ("conflict", "unknown"),
        ("missing-version", "unknown"),
        ("wrong-publisher", "unknown"),
        ("unsupported-selector", "unknown"),
    ],
)
def test_public_product_statements_accept_native_source_without_losing_unknowns(
    db, product, publisher, vendor, target, function, kind, change, expected
):
    original = (package() if kind == "appx" else facts()) | dict(
        product=product, publisher=publisher
    )
    entry = dict(
        vendor=vendor,
        product=target,
        platforms=["Windows"],
        versions=[dict(version="123.0.0.0", versionType="custom", status="affected")],
    )
    statement = dict(affected=[entry])
    if change == "conflict":
        statement["affected"].append(
            entry
            | dict(
                versions=[
                    dict(version="123.0.0.0", versionType="custom", status="unaffected")
                ]
            )
        )
    if change == "missing-version":
        original["version"] = None
    if change == "wrong-publisher":
        original["publisher"] = "Synthetic unrelated publisher"
    if change == "unsupported-selector":
        entry["modules"] = ["Synthetic unverified module"]
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        cur.execute(
            "SELECT evidence_pipeline." + function + "(%s::jsonb,%s,%s::jsonb)",
            (json.dumps(statement), vendor.lower(), json.dumps(original)),
        )
        result = cur.fetchone()[0]
    assert result["state"] == expected, result
    assert result["inventory"] == original
    if result["mapping_profile"]:
        assert result["mapping_profile"].startswith("native-windows-")


def test_migration_preserves_prior_authority_and_detects_drift(db):

    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute(
            "GRANT SELECT ON evidence_pipeline.current_native_inventory_identities TO PUBLIC"
        )
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cur)


def test_native_views_keep_all_observations_and_pinned_device_context(db, snapshot):
    from dataclasses import replace
    from uuid import uuid4
    from standalone.windows_inventory.test_store import inventory
    from standalone.windows_inventory.test_snapshot import scope
    from standalone.windows_inventory.contract import DeviceBinding
    from standalone.windows_inventory.store import register, persist
    from standalone.evidence_pipeline.persistence.authority import authorize_connection
    from standalone.evidence_pipeline.persistence.store import persist_devices

    with db.cursor() as cur:
        database_schema.verify(cur)
        authorize_connection(cur, snapshot)
    persist_devices(db, snapshot)
    binding = DeviceBinding(
        str(uuid4()), snapshot.scope.tenant_id, snapshot.records()[0]["deviceId"]
    )
    selected = replace(
        scope(),
        tenant_id=binding.tenant_id,
        scope_reference="entra-device:" + binding.device_id,
    )
    register(
        db, selected, binding, snapshot.scope.connection_id, snapshot.records()[0]["id"]
    )
    with inventory(selected, binding) as (attempt, staged):
        persist(db, attempt, staged=staged, device_attempt_id=snapshot.execution_id)
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        cur.execute(
            "SELECT count(*),count(DISTINCT receipt_id),count(*) FILTER (WHERE device_attempt_id=%s),count(*) FILTER (WHERE recognition->>'state'='unknown') FROM evidence_pipeline.current_native_inventory_identities WHERE connection_id=%s",
            (snapshot.execution_id, selected.connection_id),
        )
        assert cur.fetchone() == (2, 2, 2, 2)
        cur.execute(
            "SELECT count(*),count(*) FILTER (WHERE source_product_version_status='unknown'),count(*) FILTER (WHERE inventory_attempt_id=%s),count(*) FILTER (WHERE public_receipt_id IS NULL) FROM evidence_pipeline.current_native_inventory_product_evaluations WHERE connection_id=%s",
            (attempt.execution_id, selected.connection_id),
        )
        assert cur.fetchone() == (2, 2, 2, 2)
