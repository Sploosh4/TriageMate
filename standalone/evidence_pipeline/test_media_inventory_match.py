"""Synthetic AV1 evidence must not turn unknown conditions into applicability."""

from copy import deepcopy
import pytest
from standalone.evidence_pipeline.assessment.media_inventory_match import evaluate_media
from standalone.evidence_pipeline.assessment.windows_app_match import PACKAGE_PUBLISHER
from standalone.windows_inventory.test_manifest import metadata


def facts():
    return dict(
        source="Windows inventory",
        kind="appx",
        native_id="synthetic-av1",
        product="Microsoft.AV1VideoExtension",
        name="Microsoft.AV1VideoExtension",
        publisher=PACKAGE_PUBLISHER,
        version="1.1.50000.0",
        family_name="Microsoft.AV1VideoExtension_8wekyb3d8bbwe",
        is_bundle=False,
        is_framework=False,
        is_resource_package=False,
        user_states=[dict(sid="S-1-12-1-1-2-3-4", install_state="Installed")],
        platform="windows",
        operating_system="Windows11",
        manifest=metadata(
            name="Microsoft.AV1VideoExtension",
            publisher=PACKAGE_PUBLISHER,
            version="1.1.50000.0",
            display_name_reference="ms-resource:AppStoreName",
            display_name="AV1 Video Extension",
            display_name_basis="package_resource_text",
            resource_lookup_hresult=0,
        ),
    )


def source():
    return dict(
        affected=[
            dict(
                vendor="Microsoft",
                product="AV1 Video Extension",
                platforms=["Windows"],
                versions=[
                    dict(
                        version="1.1.0",
                        lessThan="1.1.60961.0",
                        status="affected",
                        versionType="custom",
                    )
                ],
            )
        ]
    )


def evaluate(s=None, f=None, provider="microsoft"):
    return evaluate_media(
        source() if s is None else s,
        provider=provider,
        facts=facts() if f is None else f,
    )


def test_exact_collected_name_and_version_evaluate_only_publisher_statement():
    f = facts()
    s = source()
    original = deepcopy((f, s))
    r = evaluate(s, f)
    assert r["state"] == r["product_version_status"] == "affected"
    assert r["condition_status"] == "supported" and r["applicability"] == "unknown"
    assert (f, s) == original


@pytest.mark.parametrize(
    "change",
    [
        {"source": "Intune"},
        {"product": "Microsoft.HEVCVideoExtension"},
        {"name": "Other"},
        {"publisher": "Microsoft Corporation"},
        {"family_name": "other"},
        {"kind": "registry"},
        {"is_bundle": True},
        {"is_framework": True},
        {"is_resource_package": True},
        {"is_bundle": None},
        {"native_id": ""},
        {"user_states": None},
        {"user_states": []},
        {"user_states": [{"install_state": "Staged"}]},
        {"manifest": None},
        {"operating_system": "unknown"},
        {"platform": "linux"},
    ],
)
def test_missing_or_conflicting_inventory_never_matches(change):
    r = evaluate(f=facts() | change)
    assert r["state"] == r["product_version_status"] == r["applicability"] == "unknown"


@pytest.mark.parametrize(
    "change",
    [
        {"name": "Other"},
        {"version": "1.2.3.4"},
        {"sha256": None},
        {"display_name": "AV1 Video Extensions"},
        {"display_name": None},
        {"resource_lookup_hresult": -1},
    ],
)
def test_manifest_cannot_be_substituted(change):
    f = facts()
    f["manifest"].update(change)
    assert evaluate(f=f)["product_version_status"] == "unknown"


@pytest.mark.parametrize("selector", ["platforms", "modules", "cpes"])
def test_unknown_conditions_preserve_version_claim_separately(selector):
    s = source()
    s["affected"][0][selector] = ["Unknown"]
    r = evaluate(s)
    assert r["product_version_status"] == "affected"
    assert r["state"] == r["condition_status"] == r["applicability"] == "unknown"


@pytest.mark.parametrize("selector", ["configurations", "cpeApplicability"])
def test_unimplemented_top_level_conditions_remain_unknown(selector):
    r = evaluate(source() | {selector: []})
    assert r["state"] == "unknown" and r["product_version_status"] == "affected"


def test_unlisted_version_has_no_invented_unaffected_default():
    f = facts()
    f["version"] = f["manifest"]["version"] = "2.0.0.0"
    assert evaluate(f=f)["product_version_status"] == "unknown"
    s = source()
    s["affected"][0]["defaultStatus"] = "unaffected"
    assert evaluate(s, f)["product_version_status"] == "unaffected"


def test_conflicting_and_unsupported_rules_remain_unknown():
    s = source()
    s["affected"][0]["versions"].append(
        dict(version="1.1.50000.0", status="unaffected")
    )
    assert evaluate(s)["reason"] == "conflicting_version_statuses"
    s = source()
    s["affected"][0]["versions"][0]["changes"] = []
    assert evaluate(s)["reason"] == "unsupported_or_conflicting_version_rules"


def test_conflicting_duplicate_product_statements_remain_unknown():
    s = source()
    s["affected"].append(deepcopy(s["affected"][0]))
    s["affected"][1]["versions"][0]["status"] = "unaffected"
    assert evaluate(s)["reason"] == "conflicting_product_entries"


def test_missing_fourth_version_component_is_not_invented():
    f = facts()
    f["version"] = f["manifest"]["version"] = "1.1.0.0"
    assert evaluate(f=f)["reason"] == "unsupported_or_conflicting_version_rules"


@pytest.mark.parametrize("provider", ["other", None, "Microsoft"])
def test_provider_boundary(provider):
    assert evaluate(provider=provider)["product_version_status"] == "unknown"
