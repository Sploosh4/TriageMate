"""Source identity and component accounting must not masquerade as applicability."""

from backend.database import schema as database_schema

import json
import pytest
from .test_store import db as db


@pytest.fixture
def account(db):
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute("SET LOCAL ROLE tm_mock_reader")

        def call(facts):
            cur.execute(
                "SELECT evidence_pipeline.native_inventory_accounting(%s::jsonb)",
                (json.dumps(facts),),
            )
            return cur.fetchone()[0]

        yield call


def package(**changes):
    return (
        dict(
            source="Windows inventory",
            kind="appx",
            native_id="opaque-synthetic-full-identity",
            name="Synthetic.App",
            version="1.2.3.4",
            publisher="Synthetic Publisher",
            family_name="opaque-family",
            architecture="X64",
            is_framework=False,
            is_resource_package=False,
            user_states=[dict(install_state="Installed")],
        )
        | changes
    )


def test_source_identity_is_reported_without_claiming_canonical_mapping(account):
    facts = package()
    result = account(facts)
    assert result["state"] == "reported" and result["missing_fields"] == []
    assert result["inventory"] == facts
    assert (
        result["interpretation"]
        == "reported_identity_not_canonical_product_or_applicability"
    )
    assert result["component_kind"] == "reported_non_framework_non_resource_package"


@pytest.mark.parametrize(
    "field",
    ["native_id", "name", "version", "publisher", "family_name", "architecture"],
)
@pytest.mark.parametrize("value", [None, "", "   ", False])
def test_missing_identity_fields_are_inspectable_unknowns(account, field, value):
    result = account(package(**{field: value}))
    assert result["state"] == "unknown" and result["missing_fields"] == [field]


@pytest.mark.parametrize(
    "flags,expected",
    [
        (dict(is_framework=True), "reported_framework_package"),
        (dict(is_resource_package=True), "reported_resource_package"),
        (dict(is_resource_package=None), "unknown"),
    ],
)
def test_package_component_flags_are_not_product_aliases(account, flags, expected):
    result = account(package(**flags))
    assert result["state"] == "reported" and result["component_kind"] == expected


@pytest.mark.parametrize(
    "states,expected,counts",
    [
        ([], "empty_reported_user_states", (0, 0, 0)),
        ([dict(install_state="Staged")], "no_reported_installed_user", (0, 1, 0)),
        ([dict(install_state="Paused")], "no_reported_installed_user", (0, 0, 1)),
        (
            [
                dict(install_state="Installed"),
                dict(install_state="Staged"),
                dict(install_state="Paused"),
            ],
            "reported_installed_for_some_users",
            (1, 1, 1),
        ),
        (None, "unknown", (0, 0, 0)),
    ],
)
def test_installation_states_preserve_mixed_and_missing_evidence(
    account, states, expected, counts
):
    result = account(package(user_states=states))
    assert result["installation_evidence"] == expected
    assert (
        tuple(
            result[k]
            for k in (
                "installed_user_observations",
                "staged_user_observations",
                "other_user_observations",
            )
        )
        == counts
    )


@pytest.mark.parametrize(
    "flag,expected",
    [
        (0, "reported_registry_non_system_component"),
        (1, "reported_registry_system_component"),
        (None, "unknown"),
    ],
)
def test_registry_registration_does_not_prove_installation_or_component_dependencies(
    account, flag, expected
):
    facts = package(kind="registry", system_component=flag, name=None, publisher=None)
    result = account(facts)
    assert result["missing_fields"] == ["name", "publisher"]
    assert result["installation_evidence"] == "uninstall_registration_only"
    assert result["component_kind"] == expected
    assert result["inventory"] == facts


def test_other_source_is_not_relabelled(account):
    assert account(package(source="Intune"))["reason"] == "unsupported_inventory_source"


@pytest.mark.parametrize("architecture", ["X64", "X86"])
@pytest.mark.parametrize("component", ["Minimum", "Additional"])
@pytest.mark.parametrize(
    "version,expected", [("14.40.33816", "recognized"), ("14.40.33817", "unknown")]
)
def test_vc_components_keep_distribution_architecture_and_version_conflicts(
    db, architecture, component, version, expected
):
    facts = package(
        kind="registry",
        name=f"Microsoft Visual C++ 2022 {architecture} {component} Runtime - 14.40.33816",
        publisher="Microsoft Corporation",
        version=version,
        platform="windows",
        operating_system="Windows11",
    )
    facts["product"] = facts["name"]
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        cur.execute(
            "SELECT evidence_pipeline.recognize_windows_inventory(%s::jsonb)",
            (json.dumps(facts),),
        )
        result = cur.fetchone()[0]
    assert result["state"] == expected
    assert result["applicability"] == "unknown"
    if expected == "recognized":
        assert result["family"] == f"Microsoft Visual C++ 2022 {component} Runtime"
        assert result["architecture"] == architecture.lower()
    else:
        assert result["reason"] == "conflicting_component_name_and_reported_version"


@pytest.mark.parametrize("source", ["Windows inventory", "Intune"])
def test_webview_is_not_an_edge_browser_alias(db, source):
    facts = package(
        kind="registry",
        product="Microsoft Edge WebView2 Runtime",
        publisher="Microsoft Corporation",
        version="153.0.4234.32",
        platform="windows",
        operating_system="Windows11",
    )
    facts["source"] = source
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        cur.execute(
            "SELECT evidence_pipeline.recognize_windows_inventory(%s::jsonb)",
            (json.dumps(facts),),
        )
        result = cur.fetchone()[0]
        assert result["family"] == "Microsoft Edge WebView2 Runtime"
        cur.execute(
            "SELECT evidence_pipeline.edge_inventory_status('{}'::jsonb,'microsoft',%s::jsonb)",
            (json.dumps(facts),),
        )
        assert cur.fetchone()[0]["state"] == "unknown"
