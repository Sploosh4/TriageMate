"""Exact Edge Chromium CPE bounds over an already validated inventory version."""

from standalone.evidence_pipeline.assessment.edge_inventory_match import version_key
from standalone.evidence_pipeline.assessment.windows_cpe_match import (
    evaluate_boolean_configurations,
)

_BOUNDS = (
    "versionStartIncluding",
    "versionStartExcluding",
    "versionEndIncluding",
    "versionEndExcluding",
)


def evaluate_criterion(criterion, candidate):
    def result(state, reason):
        return dict(state=state, reason=reason)

    if (
        not isinstance(candidate, tuple)
        or len(candidate) != 4
        or any(type(part) is not int or part < 0 for part in candidate)
    ):
        return result("unknown", "missing_or_invalid_edge_version")
    if (
        not isinstance(criterion, dict)
        or set(criterion)
        - {
            "criteria",
            "vulnerable",
            "matchCriteriaId",
            *_BOUNDS,
        }
        or type(criterion.get("vulnerable")) is not bool
    ):
        return result("unknown", "unsupported_criterion_fields")
    raw = criterion.get("criteria")
    parts = raw.split(":") if isinstance(raw, str) and len(raw) <= 4096 else []
    if len(parts) != 13 or parts[:5] != [
        "cpe",
        "2.3",
        "a",
        "microsoft",
        "edge_chromium",
    ]:
        return result("unknown", "other_product_or_environment_requires_evidence")
    if any(part != "*" for part in parts[6:]):
        return result("unknown", "unsupported_cpe_environment_selector")
    bounds = {key: version_key(criterion[key]) for key in _BOUNDS if key in criterion}
    if any(value is None for value in bounds.values()):
        return result("unknown", "unsupported_version_ordering")
    if all(k in bounds for k in _BOUNDS[:2]) or all(k in bounds for k in _BOUNDS[2:]):
        return result("unknown", "conflicting_version_bounds")
    lower = bounds.get(_BOUNDS[0], bounds.get(_BOUNDS[1]))
    upper = bounds.get(_BOUNDS[2], bounds.get(_BOUNDS[3]))
    if (
        lower is not None
        and upper is not None
        and (
            lower > upper
            or (lower == upper and any(k in bounds for k in (_BOUNDS[1], _BOUNDS[3])))
        )
    ):
        return result("unknown", "empty_or_reversed_version_bounds")
    if parts[5] != "*":
        exact = version_key(parts[5])
        if exact is None or bounds:
            return result("unknown", "unsupported_exact_version_and_range_combination")
        return result(
            "matched" if exact == candidate else "excluded",
            "explicit_exact_edge_version",
        )
    checks = {
        _BOUNDS[0]: lambda b: candidate >= b,
        _BOUNDS[1]: lambda b: candidate > b,
        _BOUNDS[2]: lambda b: candidate <= b,
        _BOUNDS[3]: lambda b: candidate < b,
    }
    included = all(checks[key](value) for key, value in bounds.items())
    return result("matched" if included else "excluded", "explicit_edge_version_bounds")


def evaluate_configurations(configurations, candidate):
    return evaluate_boolean_configurations(
        configurations,
        lambda value: evaluate_criterion(value, candidate),
        reason="evaluated_edge_cpe_conditions",
    )
