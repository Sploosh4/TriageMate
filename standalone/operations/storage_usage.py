"""Bounded allocated-byte sampling of explicitly configured product directories.

No file content is opened, no symlink is followed and nothing is deleted. A
completed traversal is a sample, not an atomic filesystem snapshot or hard cap.
"""

from dataclasses import dataclass
import os
from pathlib import Path
import stat
import time


@dataclass(frozen=True)
class Usage:
    allocated_bytes: int
    entries_examined: int
    incomplete_reasons: tuple[str, ...]

    @property
    def complete(self):
        return not self.incomplete_reasons


def pressure(usage, maximum_bytes):
    if maximum_bytes is None:
        return "unconfigured"
    if type(maximum_bytes) is not int or maximum_bytes < 1:
        raise ValueError("Storage allowance must be a positive byte count")
    if usage.allocated_bytes >= maximum_bytes:
        return "over_limit"
    return "below_limit" if usage.complete else "unknown"


def _directory(path):
    """Open every root component without following a symlink in its ancestry."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open("/", flags)
    try:
        for component in path.parts[1:]:
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        result, descriptor = descriptor, None
        return result
    finally:
        if descriptor is not None:
            os.close(descriptor)


def sample(
    roots, *, max_entries=100000, max_seconds=0.25, max_depth=64, clock=time.monotonic
):
    roots = tuple(roots)
    if (
        not roots
        or len(roots) > 32
        or any(
            not isinstance(path, Path)
            or not path.is_absolute()
            or ".." in path.parts
            or len(path.parts) > 128
            for path in roots
        )
    ):
        raise ValueError("Choose 1–32 explicit absolute storage directories")
    if (
        type(max_entries) is not int
        or not 1 <= max_entries <= 1000000
        or type(max_depth) is not int
        or not 0 <= max_depth <= 128
        or isinstance(max_seconds, bool)
        or not isinstance(max_seconds, (int, float))
        or not 0.001 <= max_seconds <= 10
    ):
        raise ValueError("Invalid storage sampling budget")
    deadline = clock() + max_seconds
    seen, reasons = set(), set()
    allocated = examined = 0

    def available():
        if examined >= max_entries:
            reasons.add("entry_budget")
            return False
        if clock() >= deadline:
            reasons.add("time_budget")
            return False
        return True

    def account(info):
        nonlocal examined, allocated
        examined += 1
        identity = info.st_dev, info.st_ino
        if identity in seen:
            return False
        seen.add(identity)
        blocks = getattr(info, "st_blocks", None)
        if type(blocks) is not int or blocks < 0:
            reasons.add("allocation_unavailable")
        else:
            allocated += blocks * 512
        return True

    def walk(descriptor, depth):
        if depth > max_depth:
            reasons.add("depth_budget")
            return
        try:
            with os.scandir(descriptor) as entries:
                for entry in entries:
                    if not available():
                        break
                    try:
                        info = entry.stat(follow_symlinks=False)
                        if not account(info):
                            continue
                        if stat.S_ISDIR(info.st_mode):
                            child = os.open(
                                entry.name,
                                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=descriptor,
                            )
                            try:
                                actual = os.fstat(child)
                                if (actual.st_dev, actual.st_ino) != (
                                    info.st_dev,
                                    info.st_ino,
                                ):
                                    reasons.add("concurrent_change")
                                else:
                                    walk(child, depth + 1)
                            finally:
                                os.close(child)
                        elif not (
                            stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                        ):
                            reasons.add("special_file")
                    except OSError:
                        reasons.add("unreadable_entry")
        except OSError:
            reasons.add("unreadable_directory")

    for root in roots:
        if not available():
            break
        try:
            descriptor = _directory(root)
            try:
                if account(os.fstat(descriptor)):
                    walk(descriptor, 0)
            finally:
                os.close(descriptor)
        except OSError:
            reasons.add("unreadable_root")
    return Usage(allocated, examined, tuple(sorted(reasons)))
