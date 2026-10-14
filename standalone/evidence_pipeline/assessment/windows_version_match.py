"""Evaluate one explicit NVD Windows CPE criterion against pinned source facts.

This is a criterion result, not a CVE/configuration or patch applicability result.
NVD AND/OR/negation and environmental prerequisites must be evaluated separately.
https://nvd.nist.gov/developers/vulnerabilities
"""

import re
from decimal import Decimal

_BUILD = re.compile(r"(?:0|[1-9][0-9]{0,8})(?:\.(?:0|[1-9][0-9]{0,8})){3}")
_RELEASE = re.compile(r"[0-9]{2}H[12]")
_COMPONENT = re.compile(r"[A-Za-z0-9_.-]+|\*")
_BOUNDS = (
    "versionStartIncluding",
    "versionStartExcluding",
    "versionEndIncluding",
    "versionEndExcluding",
)
# Literal Microsoft OS product identifiers present in the inspected public CNA
# records. This only excludes a different vulnerable OS target; it never asserts
# the absence of another product from the wider environment.
_WINDOWS_OS_PRODUCTS = {
    "windows_10_1607",
    "windows_10_1809",
    "windows_10_21h2",
    "windows_10_22h2",
    "windows_11_23h2",
    "windows_11_24h2",
    "windows_11_25h2",
    "windows_11_26h1",
    "windows_server_2012",
    "windows_server_2012_r2",
    "windows_server_2016",
    "windows_server_2019",
    "windows_server_2022",
    "windows_server_2025",
}


def windows_build(value):
    if not isinstance(value, str) or _BUILD.fullmatch(value) is None:
        return None
    return tuple(int(part) for part in value.split("."))


def evaluate_criterion(
    criterion,
    *,
    product,
    publisher,
    version,
    operating_system,
    release,
    os_build,
    os_architecture,
    os_processor,
):
    """Return matched/excluded/unknown with reasons; never infer absent products.

    Callers must bind all supplied device facts to the finding's original device
    receipt. Exact family/release, matching build branch and explicit architecture
    are required. Unsupported CPE encoding or extra selectors stay unknown.
    """

    def result(state, reason):
        return {"state": state, "reason": reason}

    # Device normalization deliberately stores the original numeric build as
    # canonical text. Accept that retained representation without coercing
    # whitespace, floats, Unicode digits or ambiguous formatting.
    if isinstance(os_build, str) and re.fullmatch(r"0|[1-9][0-9]{0,8}", os_build):
        os_build = int(os_build)
    build = windows_build(version)
    if (
        publisher != "microsoft"
        or product not in ("windows_10", "windows_11")
        or operating_system
        != {"windows_10": "Windows10", "windows_11": "Windows11"}.get(product)
        or not isinstance(release, str)
        or _RELEASE.fullmatch(release) is None
        or build is None
        or build[:2] != (10, 0)
        or not isinstance(os_build, (int, Decimal))
        or isinstance(os_build, bool)
        or (isinstance(os_build, Decimal) and not os_build.is_finite())
        or os_build != build[2]
    ):
        return result("unknown", "missing_or_conflicting_pinned_windows_identity")
    if not isinstance(os_architecture, str) or not isinstance(os_processor, str):
        return result("unknown", "missing_or_conflicting_pinned_architecture")
    architecture = {
        ("64-bit", "x64"): "x64",
        ("64-bit", "ARM64"): "arm64",
        ("64-bit", "arm64"): "arm64",
        ("32-bit", "x86"): "x86",
    }.get((os_architecture, os_processor))
    if architecture is None:
        return result("unknown", "missing_or_conflicting_pinned_architecture")
    if not isinstance(criterion, dict):
        return result("unknown", "invalid_criterion")
    allowed = {"criteria", "vulnerable", "matchCriteriaId", *_BOUNDS}
    if set(criterion) - allowed or type(criterion.get("vulnerable")) is not bool:
        return result("unknown", "unsupported_criterion_fields")
    cpe = criterion.get("criteria")
    parts = cpe.split(":") if isinstance(cpe, str) and len(cpe) <= 4096 else []
    if (
        len(parts) != 13
        or parts[:2] != ["cpe", "2.3"]
        or any(_COMPONENT.fullmatch(p) is None for p in parts[2:])
    ):
        return result("unknown", "unsupported_cpe_encoding")
    if parts[2:4] != ["o", "microsoft"]:
        return result("unknown", "other_product_or_environment_requires_evidence")
    if parts[4].lower() != f"{product}_{release}".lower():
        if criterion["vulnerable"] and parts[4].lower() in _WINDOWS_OS_PRODUCTS:
            return result("excluded", "different_explicit_windows_os_target")
        return result("unknown", "other_windows_product_requires_mapping")
    # Unknown editions/languages/environments must not become wildcard evidence.
    if any(parts[index] != "*" for index in (6, 7, 8, 9, 10, 12)):
        return result("unknown", "unsupported_cpe_environment_selector")
    if parts[11] not in ("*", "x64", "x86", "arm64"):
        return result("unknown", "unsupported_cpe_architecture")
    if parts[11] != "*" and parts[11] != architecture:
        return result("excluded", "explicit_architecture_mismatch")
    bounds = {key: windows_build(criterion[key]) for key in _BOUNDS if key in criterion}
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
            or (
                lower == upper
                and (
                    "versionStartExcluding" in bounds or "versionEndExcluding" in bounds
                )
            )
        )
    ):
        return result("unknown", "empty_or_reversed_version_bounds")
    if parts[5] != "*":
        exact = windows_build(parts[5])
        if exact is None or bounds:
            return result("unknown", "unsupported_exact_version_and_range_combination")
        return result(
            "matched" if build == exact else "excluded", "explicit_exact_windows_build"
        )
    if not bounds:
        return result("matched", "explicit_any_version_for_matched_windows_product")
    checks = {
        "versionStartIncluding": lambda b: build >= b,
        "versionStartExcluding": lambda b: build > b,
        "versionEndIncluding": lambda b: build <= b,
        "versionEndExcluding": lambda b: build < b,
    }
    included = all(checks[key](value) for key, value in bounds.items())
    return result(
        "matched" if included else "excluded", "explicit_windows_build_bounds"
    )
