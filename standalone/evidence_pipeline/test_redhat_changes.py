"""Generated publisher change indexes; no network or actual source fixtures."""

from datetime import datetime, timezone
import pytest
from standalone.evidence_pipeline.parsing.redhat_discovery import parse_changes


def test_revision_clocks_are_retained_without_sorting_or_publication_inference():
    rows = parse_changes(
        b"2099/rhsa-2099_123.json,2099-01-03T02:00:00+02:00\n2099/rhsa-2099_124.json,2099-01-01T00:00:00Z\n"
    )
    assert [r.advisory.advisory_id for r in rows] == ["RHSA-2099:123", "RHSA-2099:124"]
    assert rows[0].modified_at.astimezone(timezone.utc) == datetime(
        2099, 1, 3, tzinfo=timezone.utc
    )
    assert rows[0].modified_at.isoformat() == "2099-01-03T02:00:00+02:00"


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"\xff",
        b"path,date\n",
        b"../../rhsa-2099_123.json,2099-01-01T00:00:00Z\n",
        b"2099/rhsa-2099_123.json,2099-01-01\n",
        b"2099/rhsa-2099_123.json,2099-01-01T00:00:00\n",
        b"2099/rhsa-2099_123.json,2099-02-30T00:00:00Z\n",
        b"2099/rhsa-2099_123.json,2099-01-01T00:00:00Z,extra\n",
        b"2099/rhsa-2099_123.json,2099-01-01T00:00:00Z\n2099/rhsa-2099_123.json,2099-01-02T00:00:00Z\n",
        b'"2099/rhsa-2099_123.json,2099-01-01T00:00:00Z\n',
    ],
)
def test_invalid_or_ambiguous_changes_are_rejected(payload):
    with pytest.raises(ValueError):
        parse_changes(payload)
