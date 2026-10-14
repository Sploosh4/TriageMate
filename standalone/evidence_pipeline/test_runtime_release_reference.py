"""Synthetic publisher tables exercise exact correspondence and conflict refusal."""

import pytest
from standalone.evidence_pipeline.assessment.runtime_release_reference import (
    parse_reference,
)

HEADER = "| Release | NuGet Version | MSIX Version | Release Date |\n| --- | --- | --- | --- |\n"
ROW = "| 1.7.9 | 1.7.260224002 | 7000.785.2325.0 | synthetic |\n"


def test_explicit_correspondence_is_not_decoded_from_package_version():
    assert parse_reference(HEADER + ROW) == (
        dict(
            product="Microsoft.WindowsAppRuntime.1.7",
            msix_version="7000.785.2325.0",
            sdk_release="1.7.9",
            nuget_version="1.7.260224002",
        ),
    )


def test_header_positions_and_additional_columns_are_not_fixed():
    text = "| Extra | MSIX Version | Release | NuGet Version |\n| --- | --- | --- | --- |\n| ignored | 7000.785.2325.0 | 1.7.9 | 1.7.260224002 |\n"
    assert parse_reference(text) == parse_reference(HEADER + ROW)


def test_repeated_identical_rows_do_not_duplicate_mappings():
    assert parse_reference(HEADER + ROW + ROW) == parse_reference(HEADER + ROW)


def test_repeated_sections_preserve_other_runtime_families():
    other = "| 1.8.1 | 1.8.250916003 | 8000.1.2.3 | synthetic |\n"
    assert (
        len(parse_reference(HEADER + ROW + "\nSecond family\n" + HEADER + other)) == 2
    )


@pytest.mark.parametrize(
    "replacement", ["1.7.8 | 1.7.260224002", "1.7.9 | 1.7.260224001"]
)
def test_same_package_version_with_different_correspondence_is_refused(replacement):
    conflicting = ROW.replace("1.7.9 | 1.7.260224002", replacement)
    with pytest.raises(ValueError, match="Conflicting runtime release correspondences"):
        parse_reference(HEADER + ROW + conflicting)


@pytest.mark.parametrize(
    "row",
    [
        "| 1.7.9 | 1.7.260224002 | 7000.785.2325 | synthetic |\n",
        "| 1.7.9 | unknown | 7000.785.2325.0 | synthetic |\n",
        "| 1.7.9 | 1.7.260224002 | 7000.785.2325.0.1 | synthetic |\n",
        "| 1.7.9 | 1.7.260224002 |\n",
        "| 1.7.9 | 1.8.260224002 | 7000.785.2325.0 | synthetic |\n",
    ],
)
def test_incomplete_or_conflicting_row_cannot_produce_partial_acceptance(row):
    with pytest.raises(ValueError):
        parse_reference(HEADER + ROW + row)


def test_unobserved_families_and_prereleases_are_not_admitted():
    excluded = "| 1.9.1 | 1.9.260224002 | 9000.785.2325.0 | synthetic |\n| 1.7.9-preview1 | 1.7.260224002 | 7000.785.2325.0 | synthetic |\n"
    assert parse_reference(HEADER + ROW + excluded) == parse_reference(HEADER + ROW)


@pytest.mark.parametrize(
    "text", ["", "No table", "| Unrelated |\n| 1.7.9 |", None, [], False]
)
def test_missing_or_malformed_reference_is_refused(text):
    with pytest.raises(ValueError):
        parse_reference(text)


def test_duplicate_named_columns_are_refused_instead_of_choosing_first():
    text = "| Release | NuGet Version | MSIX Version | MSIX Version |\n| 1.7.9 | 1.7.260224002 | 7000.785.2325.0 | 7000.785.2325.1 |\n"
    with pytest.raises(ValueError, match="Ambiguous runtime reference columns"):
        parse_reference(text)
