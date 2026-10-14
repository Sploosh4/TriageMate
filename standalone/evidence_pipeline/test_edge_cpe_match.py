"""Generated Edge Boolean conditions and independent publisher assertions."""

from copy import deepcopy

import pytest

from standalone.evidence_pipeline.assessment.edge_cpe_match import (
    evaluate_configurations,
    evaluate_criterion,
)
from standalone.evidence_pipeline.assessment.edge_inventory_match import (
    evaluate_edge,
    version_key,
)
from .test_edge_inventory_match import FACTS, STATEMENT

CPE = "cpe:2.3:a:microsoft:edge_chromium:*:*:*:*:*:*:*:*"


def criterion(**extra):
    return dict(criteria=CPE, vulnerable=True, **extra)


def configuration(*criteria, operator="OR", negate=False):
    return [
        dict(nodes=[dict(operator=operator, negate=negate, cpeMatch=list(criteria))])
    ]


@pytest.mark.parametrize(
    "key,bound,state",
    [
        ("versionStartIncluding", "199.0.1000.5", "matched"),
        ("versionStartExcluding", "199.0.1000.5", "excluded"),
        ("versionEndIncluding", "199.0.1000.5", "matched"),
        ("versionEndExcluding", "199.0.1000.5", "excluded"),
        ("versionEndExcluding", "199.0.1000.6", "matched"),
        ("versionEndIncluding", "199.0.1000.4", "excluded"),
        ("versionEndIncluding", "199.0.1000", "unknown"),
        ("versionEndIncluding", "199.0.01000.6", "unknown"),
    ],
)
def test_bounds(key, bound, state):
    assert (
        evaluate_criterion(criterion(**{key: bound}), version_key(FACTS["version"]))[
            "state"
        ]
        == state
    )


@pytest.mark.parametrize(
    "damage",
    [
        "other",
        "architecture",
        "escaped",
        "negate_field",
        "nonbool",
        "two_lower",
        "reversed",
        "empty",
        "exact_and_range",
    ],
)
def test_unsupported_conditions(damage):
    value = criterion()
    if damage == "other":
        value["criteria"] = CPE.replace("edge_chromium", "unobserved_product")
    elif damage == "architecture":
        value["criteria"] = "cpe:2.3:a:microsoft:edge_chromium:*:*:*:*:*:*:x64:*"
    elif damage == "escaped":
        value["criteria"] = CPE.replace("edge_chromium", "edge\\:chromium")
    elif damage == "negate_field":
        value["negate"] = True
    elif damage == "nonbool":
        value["vulnerable"] = 1
    elif damage == "two_lower":
        value.update(
            versionStartIncluding="199.0.0.0", versionStartExcluding="199.0.0.0"
        )
    elif damage == "reversed":
        value.update(versionStartIncluding="200.0.0.0", versionEndIncluding="199.0.0.0")
    elif damage == "empty":
        value.update(versionStartIncluding="199.0.0.0", versionEndExcluding="199.0.0.0")
    elif damage == "exact_and_range":
        value.update(
            criteria=CPE.replace(":*:", ":199.0.1000.5:", 1),
            versionEndIncluding="200.0.0.0",
        )
    assert (
        evaluate_criterion(value, version_key(FACTS["version"]))["state"] == "unknown"
    )


def test_unknown_environment_and_vulnerable_witness():
    candidate = version_key(FACTS["version"])
    unknown = criterion()
    unknown["criteria"] = CPE.replace("edge_chromium", "unobserved_product")
    assert (
        evaluate_configurations(
            configuration(criterion(), unknown, operator="AND"), candidate
        )["state"]
        == "unknown"
    )
    assert (
        evaluate_configurations(
            configuration(criterion(), unknown, operator="OR"), candidate
        )["state"]
        == "matched"
    )
    environment = criterion()
    environment["vulnerable"] = False
    assert (
        evaluate_configurations(configuration(environment), candidate)["state"]
        == "unknown"
    )
    assert (
        evaluate_configurations(configuration(unknown, negate=True), candidate)["state"]
        == "unknown"
    )


@pytest.mark.parametrize(
    "version,default,cpe_bound,state,reason",
    [
        (
            "199.0.1000.5",
            None,
            "199.0.1000.10",
            "affected",
            "consistent_product_and_cpe_evidence",
        ),
        (
            "199.0.1000.5",
            None,
            "199.0.1000.5",
            "unknown",
            "conflicting_product_and_cpe_evidence",
        ),
        (
            "199.0.1000.10",
            None,
            "199.0.1000.10",
            "unknown",
            "incomplete_product_or_cpe_evidence",
        ),
        (
            "199.0.1000.10",
            "unaffected",
            "199.0.1000.10",
            "unaffected",
            "consistent_product_and_cpe_evidence",
        ),
        (
            "199.0.1000.10",
            "unaffected",
            "199.0.1000.11",
            "unknown",
            "conflicting_product_and_cpe_evidence",
        ),
    ],
)
def test_product_and_cpe_must_agree(version, default, cpe_bound, state, reason):
    source = deepcopy(STATEMENT)
    if default is not None:
        source["affected"][0]["defaultStatus"] = default
    source["cpeApplicability"] = configuration(criterion(versionEndExcluding=cpe_bound))
    original = deepcopy(source)
    result = evaluate_edge(
        source, provider="microsoft", facts=dict(FACTS, version=version)
    )
    assert (result["state"], result["reason"]) == (state, reason)
    assert source == original
    assert "product" in result and "cpe" in result
