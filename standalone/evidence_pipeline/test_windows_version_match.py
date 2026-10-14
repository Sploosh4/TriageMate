"""Synthetic Windows criteria preserve boundaries, contradictions and unknowns."""

import pytest
from standalone.evidence_pipeline.assessment.windows_version_match import (
    evaluate_criterion,
)

FACTS = dict(
    product="windows_11",
    publisher="microsoft",
    version="10.0.26200.100",
    operating_system="Windows11",
    release="25H2",
    os_build=26200,
    os_architecture="64-bit",
    os_processor="x64",
)
CPE = "cpe:2.3:o:microsoft:windows_11_25h2:*:*:*:*:*:*:x64:*"


@pytest.mark.parametrize(
    "bounds,state",
    [
        ({"versionEndExcluding": "10.0.26200.101"}, "matched"),
        ({"versionEndExcluding": "10.0.26200.100"}, "excluded"),
        ({"versionEndIncluding": "10.0.26200.100"}, "matched"),
        ({"versionStartIncluding": "10.0.26200.100"}, "matched"),
        ({"versionStartExcluding": "10.0.26200.100"}, "excluded"),
        (
            {
                "versionStartIncluding": "10.0.26200.99",
                "versionEndExcluding": "10.0.26200.101",
            },
            "matched",
        ),
        (
            {
                "versionStartIncluding": "10.0.26200.101",
                "versionEndIncluding": "10.0.26200.99",
            },
            "unknown",
        ),
        (
            {
                "versionStartIncluding": "10.0.26200.100",
                "versionEndExcluding": "10.0.26200.100",
            },
            "unknown",
        ),
        (
            {
                "versionStartIncluding": "10.0.26200.99",
                "versionStartExcluding": "10.0.26200.98",
            },
            "unknown",
        ),
        ({"versionEndExcluding": "25H2"}, "unknown"),
        ({"versionEndExcluding": "10.0.26200"}, "unknown"),
        ({"versionEndExcluding": "10.0.26200.0101"}, "unknown"),
    ],
)
def test_explicit_bounds(bounds, state):
    assert (
        evaluate_criterion({"criteria": CPE, "vulnerable": True, **bounds}, **FACTS)[
            "state"
        ]
        == state
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("product", "Windows 11"),
        ("publisher", "other"),
        ("operating_system", "Windows10"),
        ("release", None),
        ("version", "10.0.26100.100"),
        ("os_build", None),
        ("os_build", True),
        ("os_processor", None),
        ("os_architecture", "32-bit"),
        ("version", "10.0.26200.1-preview"),
    ],
)
def test_pinned_conflicts_stay_unknown(field, value):
    assert (
        evaluate_criterion(
            {"criteria": CPE, "vulnerable": True}, **{**FACTS, field: value}
        )["state"]
        == "unknown"
    )


@pytest.mark.parametrize(
    "cpe,state",
    [
        (CPE.replace(":x64:", ":arm64:"), "excluded"),
        (CPE.replace(":x64:", ":*:"), "matched"),
        (CPE.replace("25h2", "24h2"), "excluded"),
        (CPE.replace("windows_11", "windows_*"), "unknown"),
        (CPE + ":extra", "unknown"),
        (CPE.replace(":*:*:*:*:*:*:x64:", ":*:*:*:*:pro:*:x64:"), "unknown"),
        (CPE.replace(":*:*:*:*:*:*:x64:", ":10.0.26200.100:*:*:*:*:*:x64:"), "matched"),
        (
            CPE.replace(":*:*:*:*:*:*:x64:", ":10.0.26200.101:*:*:*:*:*:x64:"),
            "excluded",
        ),
    ],
)
def test_cpe_selectors(cpe, state):
    assert (
        evaluate_criterion({"criteria": cpe, "vulnerable": True}, **FACTS)["state"]
        == state
    )


def test_non_vulnerable_prerequisite_is_only_a_criterion_match():
    assert (
        evaluate_criterion({"criteria": CPE, "vulnerable": False}, **FACTS)["state"]
        == "matched"
    )
    assert (
        evaluate_criterion(
            {"criteria": CPE, "vulnerable": True, "unexpected": True}, **FACTS
        )["state"]
        == "unknown"
    )


def test_database_numeric_build_and_malformed_architecture():
    from decimal import Decimal

    assert (
        evaluate_criterion(
            {"criteria": CPE, "vulnerable": True},
            **{**FACTS, "os_build": Decimal(26200)},
        )["state"]
        == "matched"
    )
    for value in (Decimal("NaN"), Decimal("sNaN"), Decimal("Infinity")):
        assert (
            evaluate_criterion(
                {"criteria": CPE, "vulnerable": True}, **{**FACTS, "os_build": value}
            )["state"]
            == "unknown"
        )
    assert (
        evaluate_criterion(
            {"criteria": CPE, "vulnerable": True}, **{**FACTS, "os_processor": []}
        )["state"]
        == "unknown"
    )


@pytest.mark.parametrize(
    "build,state",
    [
        ("26200", "matched"),
        ("026200", "unknown"),
        ("26200.0", "unknown"),
        (" 26200", "unknown"),
        ("２６２００", "unknown"),
    ],
)
def test_retained_text_build_is_exact(build, state):
    assert (
        evaluate_criterion(
            {"criteria": CPE, "vulnerable": True}, **{**FACTS, "os_build": build}
        )["state"]
        == state
    )


@pytest.mark.parametrize(
    "product", ["windows_11_24h2", "windows_10_22H2", "windows_server_2025"]
)
def test_other_known_windows_os_target_is_separate_from_environment(product):
    cpe = CPE.replace("windows_11_25h2", product)
    assert evaluate_criterion({"criteria": cpe, "vulnerable": True}, **FACTS) == {
        "state": "excluded",
        "reason": "different_explicit_windows_os_target",
    }
    assert (
        evaluate_criterion({"criteria": cpe, "vulnerable": False}, **FACTS)["state"]
        == "unknown"
    )


def test_unknown_windows_alias_is_not_silently_mapped():
    cpe = CPE.replace("windows_11_25h2", "windows_server_unrecognized")
    assert (
        evaluate_criterion({"criteria": cpe, "vulnerable": True}, **FACTS)["state"]
        == "unknown"
    )
