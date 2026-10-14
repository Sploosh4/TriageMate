"""Synthetic storage changes invalidate aggregate proof without reading payloads."""

import os

import pytest

from .proof_cache import tree_state


@pytest.mark.parametrize(
    "change", ["delete", "replace", "overwrite", "add", "chmod", "symlink"]
)
def test_nested_proof_changes_invalidate_metadata_digest(tmp_path, change):
    root = tmp_path / "run"
    child = root / "nested"
    child.mkdir(parents=True)
    proof = child / "payload.bin"
    proof.write_bytes(b"synthetic-original")
    before = tree_state(root)
    assert tree_state(root) == before
    if change == "delete":
        proof.unlink()
    elif change == "replace":
        replacement = child / "new"
        replacement.write_bytes(proof.read_bytes())
        replacement.replace(proof)
    elif change == "overwrite":
        old = proof.stat()
        proof.write_bytes(b"synthetic-modified")
        os.utime(proof, ns=(old.st_atime_ns, old.st_mtime_ns))
    elif change == "add":
        (child / "receipt.json").write_text("{}")
    elif change == "chmod":
        proof.chmod(0o600 if proof.stat().st_mode & 0o077 else 0o644)
    else:
        proof.unlink()
        proof.symlink_to(root, target_is_directory=True)
    assert tree_state(root) != before


def test_missing_root_and_restoration_are_detected(tmp_path):
    root = tmp_path / "run"
    missing = tree_state(root)
    root.mkdir()
    assert tree_state(root) != missing
    root.rmdir()
    assert tree_state(root) == missing
