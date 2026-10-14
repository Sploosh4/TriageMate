"""Teams CPE conditions over exact, already identified Windows inventory."""

from standalone.evidence_pipeline.assessment.windows_app_match import (
    version_key,
    compare_versions,
)
from standalone.evidence_pipeline.assessment.windows_cpe_match import (
    evaluate_boolean_configurations,
)

BOUNDS = (
    "versionStartIncluding",
    "versionStartExcluding",
    "versionEndIncluding",
    "versionEndExcluding",
)


def evaluate_criterion(criterion, facts):
    return evaluate_application_criterion(
        criterion, facts, product="MSTeams", cpe_product="teams"
    )


def evaluate_application_criterion(criterion, facts, *, product, cpe_product):
    """Shared ordering over an independently established exact product identity."""

    def result(state, reason):
        return dict(state=state, reason=reason)

    candidate = version_key(facts.get("version"))
    if candidate is None or len(candidate) != 4:
        return result("unknown", "missing_or_invalid_application_version")
    if facts.get("product") != product or facts.get("platform") != "windows":
        return result("unknown", "unsupported_application_cpe_identity")
    if (
        not isinstance(criterion, dict)
        or set(criterion) - {"criteria", "vulnerable", "matchCriteriaId", *BOUNDS}
        or type(criterion.get("vulnerable")) is not bool
    ):
        return result("unknown", "unsupported_criterion_fields")
    raw = criterion.get("criteria")
    parts = raw.split(":") if isinstance(raw, str) and len(raw) <= 4096 else []
    if len(parts) != 13 or parts[:5] != ["cpe", "2.3", "a", "microsoft", cpe_product]:
        return result("unknown", "other_product_or_environment_requires_evidence")
    # Explicit non-Windows target platforms are incompatible even if their
    # version syntax differs. A wildcard does not identify a release channel.
    if parts[10] in {"android", "iphone_os"}:
        return result("excluded", "explicit_non_windows_target_platform")
    if parts[10] not in {"*", "windows"} or any(
        part != "*" for index, part in enumerate(parts[6:], 6) if index != 10
    ):
        return result("unknown", "unsupported_cpe_environment_selector")
    bounds = {key: version_key(criterion[key]) for key in BOUNDS if key in criterion}
    if any(value is None for value in bounds.values()):
        return result("unknown", "unsupported_version_ordering")
    if all(key in bounds for key in BOUNDS[:2]) or all(
        key in bounds for key in BOUNDS[2:]
    ):
        return result("unknown", "conflicting_version_bounds")
    lower = bounds.get(BOUNDS[0], bounds.get(BOUNDS[1]))
    upper = bounds.get(BOUNDS[2], bounds.get(BOUNDS[3]))
    if lower is not None and upper is not None:
        ordering = compare_versions(lower, upper)
        if ordering is None:
            return result("unknown", "ambiguous_version_components")
        if ordering > 0 or (
            ordering == 0 and any(key in bounds for key in (BOUNDS[1], BOUNDS[3]))
        ):
            return result("unknown", "empty_or_reversed_version_bounds")
    if parts[5] != "*":
        exact = version_key(parts[5])
        if exact is None or bounds:
            return result("unknown", "unsupported_exact_version_and_range_combination")
        ordering = compare_versions(candidate, exact)
        if ordering is None:
            return result("unknown", "ambiguous_version_components")
        return result(
            "matched" if ordering == 0 else "excluded",
            "explicit_exact_application_version",
        )
    checks = {
        BOUNDS[0]: lambda value: value >= 0,
        BOUNDS[1]: lambda value: value > 0,
        BOUNDS[2]: lambda value: value <= 0,
        BOUNDS[3]: lambda value: value < 0,
    }
    comparisons = {
        key: compare_versions(candidate, value) for key, value in bounds.items()
    }
    if any(value is None for value in comparisons.values()):
        return result("unknown", "ambiguous_version_components")
    included = all(checks[key](value) for key, value in comparisons.items())
    return result(
        "matched" if included else "excluded", "explicit_application_version_bounds"
    )


def evaluate_configurations(configurations, facts):
    return evaluate_boolean_configurations(
        configurations,
        lambda value: evaluate_criterion(value, facts),
        reason="evaluated_application_cpe_conditions",
    )
