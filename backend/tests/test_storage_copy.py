"""Synthetic verified copies preserve originals and refuse unsafe activation candidates."""

import errno
import json
import os
from pathlib import Path
import stat

import pytest

from backend.configuration import storage_copy as storage
from backend.configuration.storage_manifest import inventory_tree


def test_explicit_retained_tools_are_recorded_without_traversal_or_copy(
    trees, monkeypatch
):
    source, target = trees
    tools = source / "tools"
    tools.mkdir(mode=0o775)
    (tools / "external").symlink_to(source.parent, target_is_directory=True)
    (tools / "retained.bin").write_bytes(b"synthetic retained tool")
    before = tools.stat()
    original_open = os.open

    def no_tool_access(path, flags, *args, **kwargs):
        assert path != "tools", "Retained directory was opened for traversal"
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", no_tool_access)
    result = storage.copy_tree_verified(source, target, retained_directories=("tools",))
    assert [row.path for row in result.retained_directories] == ["tools"]
    row = result.retained_directories[0]
    assert (row.device, row.inode, row.mode, row.mtime_ns) == (
        before.st_dev,
        before.st_ino,
        stat.S_IMODE(before.st_mode),
        before.st_mtime_ns,
    )
    assert json.loads(result.json_bytes())["retained_directories"][0]["path"] == "tools"
    assert not (target / "tools").exists()
    assert (tools / "retained.bin").read_bytes() == b"synthetic retained tool"
    assert (tools / "external").is_symlink()
    assert inventory_tree(target).files == result.files
    assert inventory_tree(target).directories == result.directories


@pytest.mark.parametrize(
    "retained",
    [
        ("",),
        (".",),
        ("/tools",),
        ("../tools",),
        ("tools/",),
        ("tools", "tools"),
        ("tools", "tools/nested"),
    ],
)
def test_ambiguous_retained_selection_fails_before_destination_creation(
    trees, retained
):
    source, target = trees
    with pytest.raises(ValueError, match="Retained directories"):
        storage.copy_tree_verified(source, target, retained_directories=retained)
    assert not target.exists()


@pytest.mark.parametrize("kind", ["missing", "file", "link", "foreign_owner"])
def test_retained_selection_must_identify_existing_owned_directory(
    trees, kind, monkeypatch
):
    source, target = trees
    selected = source / "tools"
    if kind == "file":
        selected.write_bytes(b"synthetic")
    elif kind == "link":
        selected.symlink_to(source.parent, target_is_directory=True)
    elif kind == "foreign_owner":
        selected.mkdir(mode=0o700)
        original_stat = os.stat

        def foreign(path, *args, **kwargs):
            info = original_stat(path, *args, **kwargs)
            if path == "tools":
                values = list(info)
                values[4] = info.st_uid + 1
                return os.stat_result(values)
            return info

        monkeypatch.setattr(os, "stat", foreign)
    with pytest.raises(ValueError, match="retained|Retained"):
        storage.copy_tree_verified(source, target, retained_directories=("tools",))
    assert not target.exists()


def test_unlisted_link_is_rejected_even_with_a_retained_directory(trees):
    source, target = trees
    (source / "tools").mkdir(mode=0o700)
    (source / "unlisted-link").symlink_to(source.parent)
    with pytest.raises(ValueError, match="links or special"):
        storage.copy_tree_verified(source, target, retained_directories=("tools",))
    assert not target.exists()


@pytest.mark.parametrize("change", ["replace_original", "extra_destination"])
def test_retained_original_identity_and_exact_destination_are_checked(
    trees, monkeypatch, change
):
    source, target = trees
    (source / "tools").mkdir(mode=0o700)
    original_copy = storage._copy_file
    changed = False

    def mutate(src, dst, record):
        nonlocal changed
        original_copy(src, dst, record)
        if changed:
            return
        changed = True
        if change == "replace_original":
            (source / "tools").rename(source / "retained-original")
            (source / "tools").mkdir(mode=0o700)
        else:
            (target / "tools").mkdir(mode=0o700)

    monkeypatch.setattr(storage, "_copy_file", mutate)
    with pytest.raises(ValueError, match="changed during copying|differs from source"):
        storage.copy_tree_verified(source, target, retained_directories=("tools",))


@pytest.fixture
def trees(tmp_path):
    source = tmp_path / "source"
    source.mkdir(mode=0o700)
    (source / "empty").mkdir(mode=0o700)
    (source / "nested").mkdir(mode=0o700)
    for name, content, mode in [
        ("a", b"original\x00bytes", 0o644),
        ("nested/b", b"executable fixture", 0o700),
    ]:
        path = source / name
        path.write_bytes(content)
        path.chmod(mode)
    parent = tmp_path / "destination"
    parent.mkdir(mode=0o700)
    return source, parent / "stage"


def test_verified_copy_is_exact_private_and_keeps_originals(trees):
    source, target = trees
    expected = inventory_tree(source)
    original_modes = {p: p.stat().st_mode for p in source.rglob("*")}
    assert storage.copy_tree_verified(source, target) == expected
    assert inventory_tree(target) == expected == inventory_tree(source)
    assert {p: p.stat().st_mode for p in original_modes} == original_modes
    assert stat.S_IMODE((target / "a").stat().st_mode) == 0o600
    assert stat.S_IMODE((target / "nested/b").stat().st_mode) == 0o700
    assert stat.S_IMODE(target.stat().st_mode) == 0o700
    assert (target / "empty").is_dir()


@pytest.mark.parametrize("existing", ["directory", "file", "symlink"])
def test_existing_destination_is_never_overwritten(trees, existing):
    source, target = trees
    expected = inventory_tree(source)
    if existing == "directory":
        target.mkdir(mode=0o700)
        (target / "retained").write_bytes(b"keep")
    elif existing == "file":
        target.write_bytes(b"keep")
    else:
        target.symlink_to(source, target_is_directory=True)
    with pytest.raises(FileExistsError):
        storage.copy_tree_verified(source, target)
    assert inventory_tree(source) == expected
    if existing == "file":
        assert target.read_bytes() == b"keep"
    elif existing == "directory":
        assert (target / "retained").read_bytes() == b"keep"
    else:
        assert target.is_symlink()


@pytest.mark.parametrize("destination", ["same", "child", "ancestor"])
def test_overlapping_trees_are_refused(trees, destination):
    source, _ = trees
    target = {"same": source, "child": source / "stage", "ancestor": source.parent}[
        destination
    ]
    before = inventory_tree(source)
    with pytest.raises(ValueError, match="overlap"):
        storage.copy_tree_verified(source, target)
    assert inventory_tree(source) == before


def test_nonprivate_parent_and_parent_symlink_are_refused(trees):
    source, target = trees
    target.parent.chmod(0o755)
    with pytest.raises(ValueError, match="private"):
        storage.copy_tree_verified(source, target)
    assert not target.exists()
    target.parent.chmod(0o700)
    link = target.parent.parent / "link"
    link.symlink_to(target.parent, target_is_directory=True)
    with pytest.raises(OSError):
        storage.copy_tree_verified(source, link / "stage")
    assert not target.exists()


def test_copy_failure_retains_original_and_partial_stage(trees, monkeypatch):
    source, target = trees
    before = inventory_tree(source)
    original = storage._copy_file

    def disk_full(src, dst, record):
        if record.path == "nested/b":
            raise OSError(errno.ENOSPC, "Synthetic disk full")
        original(src, dst, record)

    monkeypatch.setattr(storage, "_copy_file", disk_full)
    with pytest.raises(OSError, match="disk full"):
        storage.copy_tree_verified(source, target)
    assert inventory_tree(source) == before
    assert (target / "a").read_bytes() == (source / "a").read_bytes()
    with pytest.raises(FileExistsError):
        storage.copy_tree_verified(source, target)


@pytest.mark.parametrize("changed", ["source", "destination"])
def test_changed_tree_cannot_be_reported_as_verified(trees, monkeypatch, changed):
    source, target = trees
    original = storage._copy_file

    def change_after_copy(src, dst, record):
        original(src, dst, record)
        if record.path == "nested/b":
            root = source if changed == "source" else target
            (root / "a").write_bytes(b"synthetic concurrent replacement")

    monkeypatch.setattr(storage, "_copy_file", change_after_copy)
    with pytest.raises(ValueError, match="changed during copying|differs from source"):
        storage.copy_tree_verified(source, target)
    assert source.is_dir() and target.is_dir()


def test_sync_failure_does_not_claim_success_or_remove_source(trees, monkeypatch):
    source, target = trees
    before = inventory_tree(source)

    def failed_sync(fd):
        raise OSError(errno.EIO, "Synthetic sync failure")

    monkeypatch.setattr(storage.os, "fsync", failed_sync)
    with pytest.raises(OSError, match="sync failure"):
        storage.copy_tree_verified(source, target)
    assert inventory_tree(source) == before
    assert target.exists()


def test_relative_destination_is_rejected(trees):
    source, _ = trees
    with pytest.raises(ValueError, match="absolute"):
        storage.copy_tree_verified(source, Path("relative"))


def test_empty_tree_can_be_verified(tmp_path):
    source = tmp_path / "empty"
    source.mkdir(mode=0o700)
    result = storage.copy_tree_verified(source, tmp_path / "copy")
    assert result.files == () and result.directories == ()
    assert inventory_tree(source) == inventory_tree(tmp_path / "copy")


def test_interruption_leaves_original_and_partial_copy(trees, monkeypatch):
    source, target = trees
    before = inventory_tree(source)
    original = storage._copy_file

    def interrupt(src, dst, record):
        original(src, dst, record)
        raise KeyboardInterrupt("Synthetic transition interruption")

    monkeypatch.setattr(storage, "_copy_file", interrupt)
    with pytest.raises(KeyboardInterrupt):
        storage.copy_tree_verified(source, target)
    assert inventory_tree(source) == before
    assert (target / "a").read_bytes() == (source / "a").read_bytes()


@pytest.mark.parametrize("moved", ["source", "destination"])
def test_path_replacement_cannot_activate_an_unverified_tree(trees, monkeypatch, moved):
    source, target = trees
    before = inventory_tree(source)
    original = storage._copy_file
    displaced = target.parent / (moved + "-displaced")

    def replace_location(src, dst, record):
        original(src, dst, record)
        if record.path == "nested/b":
            path = source if moved == "source" else target
            path.rename(displaced)
            path.mkdir(mode=0o700)

    monkeypatch.setattr(storage, "_copy_file", replace_location)
    with pytest.raises(ValueError, match="location changed"):
        storage.copy_tree_verified(source, target)
    assert inventory_tree(displaced) == before
    if moved == "destination":
        assert inventory_tree(source) == before
