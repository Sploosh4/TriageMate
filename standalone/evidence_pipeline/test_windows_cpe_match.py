"""Synthetic Boolean conditions must not invent vulnerable-product evidence."""

from copy import deepcopy
import pytest
from .test_windows_version_match import CPE, FACTS
from .test_windows_cna_match import entry
from standalone.evidence_pipeline.assessment.windows_cpe_match import (
    evaluate_configurations,
)
from standalone.evidence_pipeline.assessment.windows_cna_match import evaluate_record


def criterion(state="matched", vulnerable=True):
    cpe = CPE if state == "matched" else CPE.replace(":x64:", ":arm64:")
    if state == "unknown":
        cpe = "cpe:2.3:a:example:unobserved_software:*:*:*:*:*:*:*:*"
    return dict(criteria=cpe, vulnerable=vulnerable)


def configuration(*criteria, operator="OR", negate=False):
    return [
        {
            "nodes": [
                {"operator": operator, "negate": negate, "cpeMatch": list(criteria)}
            ]
        }
    ]


@pytest.mark.parametrize(
    "left,right,and_state,or_state",
    [
        ("matched", "matched", "matched", "matched"),
        ("matched", "excluded", "excluded", "matched"),
        ("matched", "unknown", "unknown", "matched"),
        ("excluded", "matched", "excluded", "matched"),
        ("excluded", "excluded", "excluded", "excluded"),
        ("excluded", "unknown", "excluded", "unknown"),
        ("unknown", "matched", "unknown", "matched"),
        ("unknown", "excluded", "excluded", "unknown"),
        ("unknown", "unknown", "unknown", "unknown"),
    ],
)
def test_boolean_conditions_retain_unknown_environment(
    left, right, and_state, or_state
):
    for operator, expected in (("AND", and_state), ("OR", or_state)):
        result = evaluate_configurations(
            configuration(criterion(left), criterion(right), operator=operator),
            facts=FACTS,
        )
        assert result["state"] == expected


def test_environment_only_is_not_a_vulnerable_product():
    for negate in (False, True):
        result = evaluate_configurations(
            configuration(
                criterion("excluded" if negate else "matched", False), negate=negate
            ),
            facts=FACTS,
        )
        assert result["state"] == "unknown"
        assert result["conditions"]["truth"] is True
        assert result["conditions"]["witness"] is False


def test_matched_environment_does_not_hide_an_unknown_vulnerable_product():
    value = configuration(criterion("matched", False), criterion("unknown"))
    result = evaluate_configurations(value, facts=FACTS)
    assert result["state"] == "unknown"
    assert result["conditions"]["truth"] is True


def test_environment_requirement_must_hold_for_matched_vulnerable_product():
    assert (
        evaluate_configurations(
            configuration(criterion(), criterion("excluded", False), operator="AND"),
            facts=FACTS,
        )["state"]
        == "excluded"
    )
    assert (
        evaluate_configurations(
            configuration(criterion(), criterion("unknown", False), operator="AND"),
            facts=FACTS,
        )["state"]
        == "unknown"
    )
    assert (
        evaluate_configurations(
            configuration(criterion(), criterion("matched", False), operator="AND"),
            facts=FACTS,
        )["state"]
        == "matched"
    )


@pytest.mark.parametrize(
    "state,expected",
    [("matched", "excluded"), ("excluded", "unknown"), ("unknown", "unknown")],
)
def test_negation_does_not_turn_absence_into_a_vulnerable_match(state, expected):
    assert (
        evaluate_configurations(
            configuration(criterion(state), negate=True), facts=FACTS
        )["state"]
        == expected
    )


def test_double_negation_restores_positive_witness():
    value = configuration(criterion(), negate=True)
    value[0]["negate"] = True
    result = evaluate_configurations(value, facts=FACTS)
    assert result["state"] == "matched"


def test_negated_environment_can_qualify_a_positive_vulnerable_branch():
    value = [
        {
            "operator": "AND",
            "nodes": [
                {"operator": "OR", "cpeMatch": [criterion()]},
                {
                    "operator": "OR",
                    "negate": True,
                    "cpeMatch": [criterion("excluded", False)],
                },
            ],
        }
    ]
    assert evaluate_configurations(value, facts=FACTS)["state"] == "matched"


@pytest.mark.parametrize(
    "value",
    [
        None,
        {},
        [],
        [None],
        [{"nodes": []}],
        [{"nodes": [None]}],
        [{"nodes": [{"cpeMatch": [criterion()]}]}],
        [{"nodes": [{"operator": "OR", "cpeMatch": []}]}],
        [{"operator": "XOR", "nodes": [{"operator": "OR", "cpeMatch": [criterion()]}]}],
        [{"negate": "false", "nodes": [{"operator": "OR", "cpeMatch": [criterion()]}]}],
        [{"nodes": [{"operator": "OR", "cpeMatch": [criterion()], "children": []}]}],
    ],
)
def test_malformed_or_unsupported_configuration_is_unknown(value):
    assert evaluate_configurations(value, facts=FACTS)["state"] == "unknown"


def test_multiple_root_nodes_require_explicit_operator():
    value = configuration(criterion())
    value[0]["nodes"] *= 2
    assert evaluate_configurations(value, facts=FACTS)["state"] == "unknown"
    value[0]["operator"] = "OR"
    assert evaluate_configurations(value, facts=FACTS)["state"] == "matched"


@pytest.mark.parametrize(
    "product_status,cpe_state,expected,reason",
    [
        ("affected", "matched", "affected", "consistent_product_and_cpe_evidence"),
        ("affected", "excluded", "unknown", "conflicting_product_and_cpe_evidence"),
        ("unaffected", "matched", "unknown", "conflicting_product_and_cpe_evidence"),
        ("unaffected", "excluded", "unaffected", "consistent_product_and_cpe_evidence"),
        ("affected", "unknown", "unknown", "incomplete_product_or_cpe_evidence"),
        ("unknown", "matched", "unknown", "incomplete_product_or_cpe_evidence"),
    ],
)
def test_cna_and_cpe_must_agree(product_status, cpe_state, expected, reason):
    product = entry()
    product["versions"][0]["status"] = product_status
    value = dict(
        affected=[product], cpeApplicability=configuration(criterion(cpe_state))
    )
    original = deepcopy(value)
    result = evaluate_record(value, provider="Microsoft", facts=FACTS)
    assert (result["state"], result["reason"]) == (expected, reason)
    assert value == original
    assert result["product"]["entries"][0]["product_index"] == 0


def test_text_configuration_cannot_be_ignored_even_when_both_numeric_statements_match():
    value = dict(
        affected=[entry()],
        cpeApplicability=configuration(criterion()),
        configurations=[
            {"lang": "en", "value": "Synthetic optional feature must be enabled"}
        ],
    )
    result = evaluate_record(value, provider="Microsoft", facts=FACTS)
    assert result["state"] == "unknown"
    assert result["reason"] == "textual_configuration_requires_evidence"


def test_missing_pinned_facts_and_unsupported_publisher_cannot_match():
    value = dict(affected=[entry()], cpeApplicability=configuration(criterion()))
    for facts, provider in (({}, "Microsoft"), (None, "Microsoft"), (FACTS, "Other")):
        assert (
            evaluate_record(value, provider=provider, facts=facts)["state"] == "unknown"
        )
