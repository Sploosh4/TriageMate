"""Verified staged copies; never activate paths, overwrite destinations or remove sources."""

import hashlib
import os
from pathlib import Path
import stat

from .paths import absolute_path
from .storage_manifest import (
    FileRecord,
    StorageManifest,
    _identity,
    _owned,
    inventory_directory,
    open_directory,
)

_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _directory(root: int, parts: tuple[str, ...]) -> int:
    descriptor = os.dup(root)
    try:
        for part in parts:
            child = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _copy_file(source: int, target: int, record: FileRecord) -> None:
    parts = tuple(record.path.split("/"))
    source_parent = _directory(source, parts[:-1])
    try:
        target_parent = _directory(target, parts[:-1])
        try:
            descriptor = os.open(
                parts[-1],
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                dir_fd=source_parent,
            )
            try:
                before = os.fstat(descriptor)
                _owned(before)
                if (
                    not stat.S_ISREG(before.st_mode)
                    or before.st_nlink != 1
                    or before.st_size != record.size
                    or before.st_mtime_ns != record.mtime_ns
                    or bool(before.st_mode & stat.S_IXUSR) != record.executable
                ):
                    raise ValueError("Source changed before copying")
                output = os.open(
                    parts[-1],
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o700 if record.executable else 0o600,
                    dir_fd=target_parent,
                )
                with os.fdopen(output, "wb") as stream:
                    digest = hashlib.sha256()
                    remaining = record.size + 1
                    size = 0
                    while remaining and (
                        block := os.read(descriptor, min(remaining, 1024 * 1024))
                    ):
                        stream.write(block)
                        digest.update(block)
                        size += len(block)
                        remaining -= len(block)
                    if (
                        size != record.size
                        or digest.hexdigest() != record.sha256
                        or _identity(os.fstat(descriptor)) != _identity(before)
                    ):
                        raise ValueError("Source changed while copying")
                    stream.flush()
                    os.utime(stream.fileno(), ns=(before.st_atime_ns, record.mtime_ns))
                    os.fsync(stream.fileno())
            finally:
                os.close(descriptor)
        finally:
            os.close(target_parent)
    finally:
        os.close(source_parent)


def _same_location(path: Path, descriptor: int) -> None:
    observed = open_directory(path)
    try:
        if not os.path.samestat(os.fstat(observed), os.fstat(descriptor)):
            raise ValueError("Storage location changed during copying")
    finally:
        os.close(observed)


def copy_tree_verified(
    source: Path, destination: Path, *, retained_directories: tuple[str, ...] = ()
) -> StorageManifest:
    """Create one private stage and return its fully compared source manifest.

    The caller drains writers and owns later activation. Any error leaves original
    files intact and any partial destination present for explicit investigation.
    Existing destinations are always refused, including prior incomplete stages.
    Explicit retained directories stay at the original location and are recorded
    separately; their contents are not copied, traversed or verified by this call.
    """
    absolute_path(str(source), "copy source")
    absolute_path(str(destination), "copy destination")
    if (
        source == destination
        or source in destination.parents
        or destination in source.parents
    ):
        raise ValueError("Source and destination trees must not overlap")
    source_fd = open_directory(source)
    try:
        expected = inventory_directory(
            source_fd, retained_directories=retained_directories
        )
        parent = open_directory(destination.parent)
        try:
            parent_info = os.fstat(parent)
            if (
                parent_info.st_uid != os.getuid()
                or stat.S_IMODE(parent_info.st_mode) != 0o700
            ):
                raise ValueError("Destination parent must be owned and private (0700)")
            os.mkdir(destination.name, mode=0o700, dir_fd=parent)
            target = os.open(destination.name, _DIRECTORY_FLAGS, dir_fd=parent)
            try:
                for relative in expected.directories:
                    parts = tuple(relative.split("/"))
                    directory = _directory(target, parts[:-1])
                    try:
                        os.mkdir(parts[-1], mode=0o700, dir_fd=directory)
                    finally:
                        os.close(directory)
                for record in expected.files:
                    _copy_file(source_fd, target, record)
                if (
                    inventory_directory(
                        source_fd, retained_directories=retained_directories
                    )
                    != expected
                ):
                    raise ValueError("Source tree changed during copying")
                copied = StorageManifest(expected.directories, expected.files)
                if inventory_directory(target) != copied:
                    raise ValueError("Copied tree differs from source manifest")
                for relative in reversed(expected.directories):
                    directory = _directory(target, tuple(relative.split("/")))
                    try:
                        os.fsync(directory)
                    finally:
                        os.close(directory)
                os.fsync(target)
                os.fsync(parent)
                _same_location(source, source_fd)
                _same_location(destination, target)
                return expected
            finally:
                os.close(target)
        finally:
            os.close(parent)
    finally:
        os.close(source_fd)
