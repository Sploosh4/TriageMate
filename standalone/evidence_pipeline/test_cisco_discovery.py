"""Synthetic Cisco index routes remain pinned to the public publisher directory."""

import pytest

from standalone.evidence_pipeline.parsing.cisco_discovery import parse_index, BASE


def test_native_filename_and_underscore_retained():
    rows = parse_index(b"2099/cisco-sa-synthetic_under-123.json\n")
    assert rows[0].advisory_id == "cisco-sa-synthetic_under-123"
    assert rows[0].url == BASE + rows[0].path


@pytest.mark.parametrize(
    "path",
    [
        "https://evil.example/a.json",
        "2099/../a.json",
        "2099/cisco-sa-x.json?x=1",
        "2099/cisco-sa-x.json#x",
        "2099/cisco-sa-x.json ",
        "",
        "2099/cisco-sa-X.json",
        "2099/other-x.json",
    ],
)
def test_ambiguous_paths_fail(path):
    with pytest.raises(ValueError):
        parse_index((path + "\n").encode())


def test_duplicate_identity_across_directories_fails():
    with pytest.raises(ValueError, match="Repeated"):
        parse_index(b"2099/cisco-sa-x.json\n2098/cisco-sa-x.json\n")
