"""Synthetic malformed provider offsets must not alter observation dates."""

from datetime import datetime

import pytest

from standalone.evidence_pipeline.parsing.devices import timestamp
from standalone.evidence_pipeline.parsing.msrc_publications import release_date
from standalone.evidence_pipeline.parsing.source_time import source_datetime
from standalone.evidence_pipeline.parsing.vulnerability_events import reported_time


@pytest.mark.parametrize(
    "offset", ["+00:60", "-00:60", "+01:99", "+24:00", "+0060", "+00:00:60"]
)
@pytest.mark.parametrize(
    "parser", [lambda v: timestamp(v, "seen"), release_date, reported_time]
)
def test_provider_paths_reject_malformed_offsets(parser, offset):
    with pytest.raises(ValueError):
        parser("2026-09-21T00:30:00" + offset)


@pytest.mark.parametrize("offset", ["Z", "+00:00", "-07:30", "+05:45", "+0530", "+05"])
def test_valid_offsets_keep_existing_interpretation(offset):
    value = "2026-09-21T00:30:00.1234567" + offset
    assert source_datetime(value) == datetime.fromisoformat(value)
    assert reported_time(value)[0] == value
    assert timestamp(value, "seen") is not None
    assert release_date(value) == datetime.fromisoformat(value)


def test_naive_assessment_time_remains_unknown_and_raw():
    value = "2026-09-21T00:30:00.1234567"
    assert reported_time(value) == (value, None)
    with pytest.raises(ValueError):
        timestamp(value, "seen")
    with pytest.raises(ValueError):
        release_date(value)
