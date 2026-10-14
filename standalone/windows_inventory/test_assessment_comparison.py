"""Synthetic boundary cases for source-supported Windows comparisons."""

from dataclasses import replace
from datetime import datetime, timezone, timedelta
import pytest
from .assessment_comparison import DeviceContext, compare

NOW = datetime(2026, 9, 21, tzinfo=timezone.utc)
CONTEXT = DeviceContext(
    "synthetic",
    "11111111-1111-1111-1111-111111111111",
    "22222222-2222-2222-2222-222222222222",
    "synthetic-device",
)
ROW = dict(
    deviceId="synthetic-device",
    softwareVendor="synthetic",
    softwareName="product",
    softwareVersion="2.0",
    numberOfWeaknesses=0,
)


def run(**changes):
    args = dict(
        local_context=CONTEXT,
        export_context=CONTEXT,
        local_version="2.0",
        local_observed_at=NOW,
        exported_at=NOW,
        assessed=[ROW],
        unsupported=[],
        aliases={("synthetic", "product")},
        complete=True,
    )
    args.update(changes)
    return compare(**args)


def test_exact_zero_preserved_without_claiming_assessment_time_or_coverage():
    r = run()
    assert r["state"] == "assessed_product_version_correspondence"
    assert r["source_records"]["assessed"][0]["numberOfWeaknesses"] == 0
    assert r["assessment_time"] is None and r["vulnerability_coverage"] == "unverified"
    assert r["temporal_alignment"] == "unverified_assessment_time"


@pytest.mark.parametrize(
    "field,value",
    [
        ("origin", "lab"),
        ("tenant_id", "33333333-3333-3333-3333-333333333333"),
        ("registration_id", "33333333-3333-3333-3333-333333333333"),
        ("defender_device_id", "historical-device"),
    ],
)
def test_other_scope_or_historical_instance_rejected(field, value):
    with pytest.raises(ValueError, match="differs"):
        run(export_context=replace(CONTEXT, **{field: value}))


def test_foreign_row_and_incomplete_export_rejected():
    with pytest.raises(ValueError, match="another device"):
        run(assessed=[dict(ROW, deviceId="another-device")])
    with pytest.raises(ValueError, match="Complete"):
        run(complete=False)


@pytest.mark.parametrize(
    "assessed,unsupported,version,aliases,state",
    [
        (
            [],
            [ROW],
            "2.0",
            {("synthetic", "product")},
            "explicit_non_cpe_product_version_correspondence",
        ),
        (
            [ROW],
            [ROW],
            "2.0",
            {("synthetic", "product")},
            "overlapping_source_representations",
        ),
        ([ROW], [], "2.1", {("synthetic", "product")}, "product_version_mismatch"),
        ([ROW], [], "2.0", set(), "unmatched_not_unsupported"),
        ([], [], None, set(), "incomplete_local_identity"),
    ],
)
def test_unknown_mismatch_and_overlap_are_distinct(
    assessed, unsupported, version, aliases, state
):
    assert (
        run(
            assessed=assessed,
            unsupported=unsupported,
            local_version=version,
            aliases=aliases,
        )["state"]
        == state
    )


def test_old_export_and_first_seen_do_not_become_fresh_assessment():
    r = run(
        exported_at=NOW - timedelta(days=1),
        assessed=[dict(ROW, softwareFirstSeenTimestamp=NOW.isoformat())],
    )
    assert r["export_predates_local_observation"]
    assert r["assessment_time"] is None


def test_source_records_not_mutated():
    r = run()
    r["source_records"]["assessed"][0]["softwareVersion"] = "changed"
    assert ROW["softwareVersion"] == "2.0"
