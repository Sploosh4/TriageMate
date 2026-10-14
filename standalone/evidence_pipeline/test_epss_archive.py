"""Dated FIRST routes bind headerless/history evidence without changing current."""

from dataclasses import replace
from datetime import date
import pytest
from standalone.evidence_pipeline.collection.public_transport import endpoint
from standalone.evidence_pipeline.parsing.public_inputs import parse_epss_csv
from standalone.evidence_pipeline.parsing.epss_stream import parse_epss_file
from .test_epss_stream import saved
from .test_public_inputs import scope


@pytest.mark.parametrize("value", [None, "2021-04-14", "2024-02-29", "2026-09-12"])
def test_fixed_date_route(value):
    assert endpoint("FIRST", score_date=value) == (
        "https://epss.empiricalsecurity.com/epss_scores-"
        + (value or "current")
        + ".csv.gz"
    )


@pytest.mark.parametrize(
    "value",
    [
        True,
        20260912,
        "20260912",
        "2026-02-29",
        "2021-04-13",
        "../../secret",
        "2026-09-12?x=1",
        "２０２６-09-12",
    ],
)
def test_archive_date_rejects_invalid_routes(value):
    with pytest.raises(ValueError):
        endpoint("FIRST", score_date=value)


@pytest.mark.parametrize(
    "options",
    [
        dict(source="CISA"),
        dict(source="FIRST", cve="CVE-2099-12345"),
        dict(source="FIRST", month="2026-Sep"),
        dict(source="FIRST", input_kind="kev"),
        dict(source="FIRST", vendor_path="anything"),
    ],
)
def test_date_does_not_override_another_route(options):
    with pytest.raises(ValueError):
        endpoint(**options, score_date="2026-09-12")


@pytest.mark.parametrize("offset", ["+0000", "+00:00", "Z"])
def test_archive_timestamp_formats_preserve_date_and_exact_score(tmp_path, offset):
    from datetime import datetime, timezone
    from decimal import Decimal

    chosen = replace(
        scope("FIRST"), scope_reference=endpoint("FIRST", score_date="2023-02-01")
    )
    raw = (
        f"#model_version:synthetic-v2,score_date:2023-02-01T00:00:00{offset}\n"
        "cve,epss,percentile\nCVE-2099-12345,0.97974000000000006,1\n"
    ).encode()
    for feed in (
        parse_epss_csv(raw, scope=chosen),
        parse_epss_file(saved(tmp_path, raw), scope=chosen),
    ):
        assert feed.score_timestamp == datetime(2023, 2, 1, tzinfo=timezone.utc)
        assert feed.score_date == date(2023, 2, 1)
        assert list(feed.records)[0].probability == Decimal("0.97974000000000006")


@pytest.mark.parametrize(
    "stamp",
    [
        "2023-02-01T00:00:00",
        "2023-02-01T00:00:00+2500",
        "2023-02-02T00:00:00+0000",
        "2023-02-01T00:00:00+000",
    ],
)
def test_archive_rejects_invalid_or_wrong_day_timestamps(stamp):
    chosen = replace(
        scope("FIRST"), scope_reference=endpoint("FIRST", score_date="2023-02-01")
    )
    raw = f"#model_version:synthetic-v2,score_date:{stamp}\ncve,epss,percentile\n".encode()
    with pytest.raises(ValueError):
        parse_epss_csv(raw, scope=chosen)
