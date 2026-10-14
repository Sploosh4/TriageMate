"""Synthetic filesystem usage counts allocations once without following links."""

import os
from pathlib import Path

import pytest

from .storage_usage import Usage, pressure, sample


def allocated(*paths):
    return sum(path.lstat().st_blocks * 512 for path in paths)


def test_nested_roots_and_hardlinks_count_each_allocation_once(tmp_path):
    child = tmp_path / "child"
    child.mkdir()
    data = child / "synthetic.bin"
    data.write_bytes(b"synthetic" * 1000)
    os.link(data, tmp_path / "same-data")
    result = sample([tmp_path, child], max_seconds=10)
    assert result.complete
    assert result.allocated_bytes == allocated(tmp_path, child, data)


def test_symlinks_do_not_include_external_targets_or_follow_root_ancestors(tmp_path):
    inside, outside = tmp_path / "inside", tmp_path / "outside"
    inside.mkdir()
    outside.mkdir()
    (outside / "synthetic.bin").write_bytes(b"synthetic" * 10000)
    link = inside / "link"
    link.symlink_to(outside, target_is_directory=True)
    result = sample([inside], max_seconds=10)
    assert result.complete and result.allocated_bytes == allocated(inside, link)
    blocked = sample([link])
    assert not blocked.complete and blocked.allocated_bytes == 0
    assert not sample([link / "nested"]).complete


def test_sparse_files_use_allocated_bytes_not_logical_length(tmp_path):
    data = tmp_path / "synthetic-sparse.bin"
    with data.open("wb") as stream:
        stream.seek(10_000_000)
        stream.write(b"synthetic")
    result = sample([tmp_path], max_seconds=10)
    assert result.allocated_bytes == allocated(tmp_path, data)
    assert result.allocated_bytes < data.stat().st_size


def test_budgets_and_missing_roots_are_explicit(tmp_path):
    child = tmp_path / "child"
    child.mkdir()
    (child / "synthetic.txt").write_text("synthetic")
    assert "entry_budget" in sample([tmp_path], max_entries=1).incomplete_reasons
    assert "depth_budget" in sample([tmp_path], max_depth=0).incomplete_reasons
    ticks = iter([0, 1])
    assert (
        "time_budget"
        in sample([tmp_path], clock=lambda: next(ticks)).incomplete_reasons
    )
    assert "unreadable_root" in sample([tmp_path / "missing"]).incomplete_reasons


def test_special_files_are_not_opened(tmp_path):
    os.mkfifo(tmp_path / "synthetic-pipe")
    assert "special_file" in sample([tmp_path]).incomplete_reasons


@pytest.mark.parametrize(
    "usage,limit,state",
    [
        (Usage(100, 1, ()), None, "unconfigured"),
        (Usage(100, 1, ()), 100, "over_limit"),
        (Usage(100, 1, ("entry_budget",)), 50, "over_limit"),
        (Usage(100, 1, ("entry_budget",)), 200, "unknown"),
        (Usage(100, 1, ()), 200, "below_limit"),
    ],
)
def test_partial_measurement_cannot_clear_pressure(usage, limit, state):
    assert pressure(usage, limit) == state


@pytest.mark.parametrize(
    "roots,options",
    [
        ([], {}),
        ([Path("relative")], {}),
        ([Path("/tmp/../")], {}),
        ([Path("/tmp")], {"max_entries": True}),
        ([Path("/tmp")], {"max_seconds": float("nan")}),
        ([Path("/tmp")], {"max_depth": 129}),
    ],
)
def test_invalid_sampling_requests_are_rejected(roots, options):
    with pytest.raises(ValueError):
        sample(roots, **options)
