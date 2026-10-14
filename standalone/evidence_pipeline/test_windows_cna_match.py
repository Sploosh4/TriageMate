from copy import deepcopy
import pytest
from standalone.evidence_pipeline.assessment.windows_cna_match import evaluate_products
from .test_windows_version_match import FACTS


def entry():
    return dict(
        vendor="Microsoft",
        product="Windows 11 Version 25H2",
        platforms=["ARM64-based Systems", "x64-based Systems"],
        versions=[
            dict(
                version="10.0.26200.0",
                lessThan="10.0.26200.200",
                versionType="custom",
                status="affected",
            )
        ],
    )


def evaluate(entries, version="10.0.26200.100"):
    return evaluate_products(
        entries, provider="Microsoft", facts={**FACTS, "version": version}
    )


@pytest.mark.parametrize(
    "version,state",
    [
        ("10.0.26200.0", "affected"),
        ("10.0.26200.199", "affected"),
        ("10.0.26200.200", "unknown"),
        ("10.0.26200.201", "unknown"),
    ],
)
def test_exclusive_bound_and_absent_default(version, state):
    assert evaluate([entry()], version)["state"] == state


def test_explicit_default_and_inclusive_bound():
    value = entry()
    value["defaultStatus"] = "unaffected"
    assert evaluate([value], "10.0.26200.200")["state"] == "unaffected"
    value["versions"][0]["lessThanOrEqual"] = value["versions"][0].pop("lessThan")
    assert evaluate([value], "10.0.26200.200")["state"] == "affected"
    assert evaluate([value], "10.0.26200.201")["state"] == "unaffected"


def test_changes_are_sorted_and_apply_at_boundary():
    value = entry()
    value["versions"][0]["changes"] = [
        dict(at="10.0.26200.150", status="affected"),
        dict(at="10.0.26200.100", status="unaffected"),
    ]
    assert evaluate([value], "10.0.26200.99")["state"] == "affected"
    assert evaluate([value], "10.0.26200.100")["state"] == "unaffected"
    assert evaluate([value], "10.0.26200.150")["state"] == "affected"


@pytest.mark.parametrize(
    "change",
    [
        {"lessThanOrEqual": "10.0.26200.200"},
        {"lessThan": "10.0.26100.100"},
        {"lessThan": "10.0.26200.preview"},
        {"versionType": "semver"},
        {"changes": [dict(at="10.0.26200.200", status="unaffected")]},
        {
            "changes": [
                dict(at="10.0.26200.100", status="affected"),
                dict(at="10.0.26200.100", status="unaffected"),
            ]
        },
        {"changes": {}},
        {"status": "fixed"},
        {"unexpected": True},
    ],
)
def test_malformed_and_conflicting_ranges_stay_unknown(change):
    value = entry()
    value["versions"][0].update(change)
    assert evaluate([value])["state"] == "unknown"


def test_overlapping_status_conflicts_do_not_depend_on_order():
    value = entry()
    other = deepcopy(value["versions"][0])
    other["status"] = "unaffected"
    value["versions"].append(other)
    assert evaluate([value])["state"] == "unknown"
    value["versions"].reverse()
    assert evaluate([value])["state"] == "unknown"
    first = entry()
    second = entry()
    second["versions"][0]["status"] = "unaffected"
    assert evaluate([first, second])["state"] == "unknown"
    assert evaluate([second, first])["state"] == "unknown"


@pytest.mark.parametrize(
    "change",
    [
        {"platforms": None},
        {"platforms": ["unknown"]},
        {"modules": ["optional feature"]},
        {"defaultStatus": "fixed"},
    ],
)
def test_unsupported_product_constraints(change):
    value = entry()
    value.update(change)
    assert evaluate([value])["state"] == "unknown"


def test_exact_versions_open_ranges_and_attribution_indexes():
    value = entry()
    value["versions"] = [dict(version="10.0.26200.100", status="unaffected")]
    result = evaluate([value])
    assert result["state"] == "unaffected"
    assert result["entries"][0]["version_indexes"] == [0]
    assert evaluate([value], "10.0.26200.101")["state"] == "unknown"
    value["versions"] = [
        dict(
            version="10.0.26200.0",
            lessThan="*",
            versionType="custom",
            status="affected",
        )
    ]
    assert evaluate([value])["state"] == "affected"
    assert (
        evaluate_products([value], provider="Other", facts=FACTS)["state"] == "unknown"
    )
    assert (
        evaluate_products(
            [value], provider="Microsoft", facts={**FACTS, "os_build": 26100}
        )["state"]
        == "unknown"
    )


@pytest.mark.parametrize(
    "bad",
    [
        {"vendor": "Microsoft", "product": None},
        {"product": "Windows 11 Version 25H2"},
        {"vendor": [], "product": "Windows 11 Version 25H2"},
    ],
)
def test_malformed_identity_cannot_hide_a_conflicting_assertion(bad):
    assert evaluate([entry(), bad])["state"] == "unknown"


def test_exact_version_cannot_silently_ignore_changes():
    value = entry()
    value["versions"] = [dict(version="10.0.26200.100", status="affected", changes={})]
    assert evaluate([value])["state"] == "unknown"


def test_evaluation_preserves_original_source_and_facts():
    value = entry()
    before = deepcopy(value)
    facts = deepcopy(FACTS)
    original_facts = deepcopy(facts)
    evaluate_products([value], provider="Microsoft", facts=facts)
    assert value == before and facts == original_facts


def test_empty_versions_cannot_fall_through_to_default():
    value = entry()
    value.update(versions=[], defaultStatus="unaffected")
    assert evaluate([value])["state"] == "unknown"
