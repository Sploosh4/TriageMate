"""CVE/NVD Boolean CPE conditions over explicitly pinned Windows facts.

Matching an environmental prerequisite is not evidence that that product is
vulnerable. Unknown facts use three-valued logic, including under negation.
Only the published configuration/nodes/cpeMatch shape is supported.
"""

from standalone.evidence_pipeline.assessment.windows_version_match import (
    evaluate_criterion,
)


def _and(values):
    return False if False in values else None if None in values else True


def _or(values):
    return True if True in values else None if None in values else False


def _not(value):
    return None if value is None else not value


def _unknown(reason):
    return dict(truth=None, witness=None, negative_witness=None, reason=reason)


def _combine(children, operator, negate=False):
    """Track a vulnerable-product witness through both Boolean polarities.

    The negative witness permits double negation without treating the absence
    of a vulnerable product as a positive vulnerable-product match.
    """
    truths = [child["truth"] for child in children]
    truth = (_and if operator == "AND" else _or)(truths)
    positive = [child["witness"] for child in children]
    negative = [child["negative_witness"] for child in children]
    witness = _and([truth, _or(positive)]) if operator == "AND" else _or(positive)
    negative_witness = (
        _or(negative) if operator == "AND" else _and([_not(truth), _or(negative)])
    )
    if negate:
        truth, witness, negative_witness = _not(truth), negative_witness, witness
    return dict(
        truth=truth,
        witness=witness,
        negative_witness=negative_witness,
        operator=operator,
        negate=negate,
        children=children,
    )


def evaluate_configurations(configurations, *, facts):
    """Evaluate conditions, retaining positional source evidence and unknowns.

    A matched result requires both satisfied Boolean conditions and a matching
    vulnerable product. An excluded result concerns this configuration only;
    it is not a general assertion that the device or CVE is unaffected.
    """

    def evaluate(value):
        try:
            return evaluate_criterion(value, **facts)
        except TypeError:
            return dict(state="unknown", reason="incomplete_pinned_facts")

    return evaluate_boolean_configurations(
        configurations, evaluate, reason="evaluated_windows_cpe_conditions"
    )


def evaluate_boolean_configurations(configurations, evaluate, *, reason):
    """Share Boolean/witness semantics; product-specific callbacks own identity."""

    def leaf(value):
        evaluation = evaluate(value)
        truth = {"matched": True, "excluded": False, "unknown": None}[
            evaluation["state"]
        ]
        return dict(
            truth=truth,
            witness=truth
            if isinstance(value, dict) and value.get("vulnerable") is True
            else False,
            negative_witness=False,
            reason=evaluation["reason"],
        )

    def group(value, key, evaluate_child):
        if not isinstance(value, dict) or set(value) - {key, "operator", "negate"}:
            return _unknown("unsupported_configuration_fields")
        children = value.get(key)
        if not isinstance(children, list) or not children:
            return _unknown("empty_or_invalid_configuration")
        operator = value.get("operator")
        # Missing root operator is unambiguous only for a singleton node.
        if operator is None and key == "nodes" and len(children) == 1:
            operator = "OR"
        if (
            operator not in ("AND", "OR")
            or type(value.get("negate", False)) is not bool
        ):
            return _unknown("unsupported_configuration_operator")
        return _combine(
            [evaluate_child(child) for child in children],
            operator,
            value.get("negate", False),
        )

    if not isinstance(configurations, list) or not configurations:
        result = _unknown("empty_or_invalid_configurations")
    else:
        result = _combine(
            [
                group(value, "nodes", lambda node: group(node, "cpeMatch", leaf))
                for value in configurations
            ],
            "OR",
        )
    state = (
        "excluded"
        if result["truth"] is False
        else "matched"
        if result["witness"] is True
        else "unknown"
    )
    return dict(state=state, reason=reason, conditions=result)
