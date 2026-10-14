"""An advisory identifier never becomes a CVE or a made-up alias."""

import pytest

from standalone.evidence_pipeline.parsing.cvrf_identity import native_identity


@pytest.mark.parametrize(
    "value",
    [
        "ADV160001",
        "ADV990001",
        "CVE-2022-2601-M",
        "CVE-2022-3775-M",
        "CVE-2023-32002 - M",
        "CVE-2023-38039 mariner - do not use this one",
    ],
)
def test_advisory_keeps_native_identity_without_cve(value):
    assert native_identity(value) == (value, None)


def test_cve_keeps_existing_identity():
    assert native_identity("CVE-2016-1234") == ("CVE-2016-1234", "CVE-2016-1234")


@pytest.mark.parametrize(
    "value",
    [
        "CVE-2023-32002- M",
        "CVE-2023-32002 -M",
        "CVE-2023-32002  -  M",
        "CVE-2023-32002 - m",
        "CVE-2023-32002\t- M",
    ],
)
def test_unobserved_spacing_is_not_silently_normalized(value):
    with pytest.raises(ValueError):
        native_identity(value)


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        "adv160001",
        "ADV16000",
        "ADV1600011",
        "ADV１６０００１",
        "CVE-ADV160001",
        "unidentified",
        "CVE-2022-2601-m",
        "CVE-2022-2601-X",
        "ADV160001-M",
        "CVE-2022-2601-M-M",
    ],
)
def test_unknown_or_malformed_identifier_is_not_invented(value):
    with pytest.raises(ValueError):
        native_identity(value)
