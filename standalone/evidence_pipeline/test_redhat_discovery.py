"""Synthetic discovery lists cannot redirect downloads or collapse source identities."""

import pytest

from standalone.evidence_pipeline.parsing import redhat_discovery as discovery


def test_index_preserves_exact_native_ids_and_order():
    rows = discovery.parse_index(b"2001/rhsa-2001_058.json\n2026/rhsa-2026_9874.json\n")
    assert [row.advisory_id for row in rows] == ["RHSA-2001:058", "RHSA-2026:9874"]
    assert rows[0].url == discovery.BASE + rows[0].path


@pytest.mark.parametrize(
    "path",
    [
        "https://evil.example/x.json",
        "2026/../x.json",
        "2026/rhsa-2026_1234.json?x=1",
        "2026/rhsa-2026_1234.json#x",
        "2026/rhsa-2026_1234.json ",
        "",
        "2026/rhsa-2026_1234.json\x00",
        "2026/RHSA-2026_1234.json",
    ],
)
def test_unsafe_or_ambiguous_paths_rejected(path):
    with pytest.raises(ValueError):
        discovery.parse_index((path + "\n").encode())


def test_duplicates_and_bounds(monkeypatch):
    line = b"2026/rhsa-2026_1234.json\n"
    with pytest.raises(ValueError, match="Repeated"):
        discovery.parse_index(line * 2)
    monkeypatch.setattr(discovery, "MAX_ADVISORIES", 0)
    with pytest.raises(ValueError, match="record limit"):
        discovery.parse_index(line)


def test_directory_year_and_notice_type_are_not_inferred():
    rows = discovery.parse_index(
        b"2002/rhsa-2001_164.json\n2003/rhba-2003_308.json\n2026/rhea-2026_1234.json\n"
    )
    assert [r.advisory_id for r in rows] == [
        "RHSA-2001:164",
        "RHBA-2003:308",
        "RHEA-2026:1234",
    ]
