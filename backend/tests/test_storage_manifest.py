"""Synthetic source manifests reject links, unsafe permissions and changing trees."""

import hashlib
import os
from pathlib import Path

import pytest

from backend.configuration import storage_manifest as storage


def test_manifest_preserves_empty_directories_exact_bytes_and_source_metadata(tmp_path):
    (tmp_path / "empty").mkdir(mode=0o700)
    (tmp_path / "nested").mkdir(mode=0o700)
    paths = [tmp_path / "z.bin", tmp_path / "nested/é.txt"]
    payloads = [bytes(range(256)) * 8193, b"original\x00bytes\r\n"]
    for index, (path, payload) in enumerate(zip(paths, payloads, strict=True)):
        path.write_bytes(payload)
        path.chmod(0o700 if index else 0o600)
    before = [(path.stat().st_mtime_ns, path.stat().st_mode) for path in paths]
    manifest = storage.inventory_tree(tmp_path)
    assert manifest == storage.inventory_tree(tmp_path)
    assert manifest.directories == ("empty", "nested")
    records = {row.path: row for row in manifest.files}
    for path, payload in zip(paths, payloads, strict=True):
        row = records[path.relative_to(tmp_path).as_posix()]
        assert row.sha256 == hashlib.sha256(payload).hexdigest()
        assert row.size == len(payload)
        assert row.mtime_ns == path.stat().st_mtime_ns
    assert records["nested/é.txt"].executable
    assert not records["z.bin"].executable
    assert manifest.byte_count == sum(map(len, payloads))
    assert manifest.sha256 == hashlib.sha256(manifest.json_bytes()).hexdigest()
    assert str(tmp_path).encode() not in manifest.json_bytes()
    assert [(p.stat().st_mtime_ns, p.stat().st_mode) for p in paths] == before
    assert [p.read_bytes() for p in paths] == payloads


@pytest.mark.parametrize("kind", ["file_link", "directory_link", "hard_link", "fifo"])
def test_links_and_special_files_are_not_silently_copied(tmp_path, kind):
    source = tmp_path / "source"
    source.mkdir(mode=0o700)
    original = tmp_path / "original"
    original.write_bytes(b"synthetic")
    original.chmod(0o600)
    if kind == "file_link":
        (source / "bad").symlink_to(original)
    elif kind == "directory_link":
        (source / "bad").symlink_to(tmp_path, target_is_directory=True)
    elif kind == "hard_link":
        os.link(original, source / "bad")
    else:
        os.mkfifo(source / "bad", 0o600)
    with pytest.raises(ValueError, match="links or special"):
        storage.inventory_tree(source)


def test_symlink_ancestor_is_rejected(tmp_path):
    (tmp_path / "real").mkdir(mode=0o700)
    (tmp_path / "link").symlink_to(tmp_path / "real", target_is_directory=True)
    with pytest.raises(OSError):
        storage.inventory_tree(tmp_path / "link")


@pytest.mark.parametrize("directory", [False, True])
def test_other_user_write_permissions_are_rejected(tmp_path, directory):
    target = tmp_path if directory else tmp_path / "file"
    if not directory:
        target.write_bytes(b"synthetic")
    target.chmod(0o770 if directory else 0o660)
    with pytest.raises(ValueError, match="not writable"):
        storage.inventory_tree(tmp_path)


@pytest.mark.parametrize("change", ["append", "replace", "add", "remove"])
def test_source_changes_during_hashing_are_rejected(tmp_path, monkeypatch, change):
    source = tmp_path / "record"
    source.write_bytes(b"synthetic original")
    source.chmod(0o600)
    original_read = os.read
    changed = False

    def changing(descriptor, size):
        nonlocal changed
        data = original_read(descriptor, size)
        if not changed:
            changed = True
            if change == "append":
                with source.open("ab") as stream:
                    stream.write(b"changed")
            elif change == "replace":
                replacement = tmp_path / "replacement"
                replacement.write_bytes(b"other bytes")
                replacement.chmod(0o600)
                replacement.replace(source)
            elif change == "add":
                (tmp_path / "new").write_bytes(b"added")
            else:
                source.unlink()
        return data

    monkeypatch.setattr(storage.os, "read", changing)
    with pytest.raises(ValueError, match="changed while hashing"):
        storage.inventory_tree(tmp_path)


def test_missing_and_relative_sources_are_rejected(tmp_path):
    with pytest.raises(FileNotFoundError):
        storage.inventory_tree(tmp_path / "missing")
    with pytest.raises(ValueError, match="absolute"):
        storage.inventory_tree(Path("relative"))


def test_foreign_owner_is_rejected_without_changing_ownership(tmp_path, monkeypatch):
    monkeypatch.setattr(storage.os, "getuid", lambda: tmp_path.stat().st_uid + 1)
    with pytest.raises(ValueError, match="owned"):
        storage.inventory_tree(tmp_path)


def test_symlink_intermediate_component_is_rejected(tmp_path):
    (tmp_path / "real").mkdir(mode=0o700)
    (tmp_path / "real/child").mkdir(mode=0o700)
    (tmp_path / "link").symlink_to(tmp_path / "real", target_is_directory=True)
    with pytest.raises(OSError):
        storage.inventory_tree(tmp_path / "link/child")
