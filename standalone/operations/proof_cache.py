"""Filesystem metadata invalidators for previously verified aggregate proof."""

import hashlib
import os
import stat


def tree_state(root):
    """Hash names and metadata, never payloads or symlink targets.

    This is not evidence verification. Callers must validate complete proof before
    caching, and compare again afterward to reject concurrent storage changes.
    """
    digest = hashlib.sha256()

    def visit(path, relative):
        try:
            info = path.lstat()
        except FileNotFoundError:
            digest.update(repr((relative, None)).encode())
            return
        digest.update(
            repr(
                (
                    relative,
                    info.st_dev,
                    info.st_ino,
                    info.st_mode,
                    info.st_uid,
                    info.st_gid,
                    info.st_size,
                    info.st_mtime_ns,
                    info.st_ctime_ns,
                )
            ).encode()
        )
        if stat.S_ISDIR(info.st_mode):
            with os.scandir(path) as entries:
                names = sorted(entry.name for entry in entries)
            for name in names:
                visit(path / name, relative + (name,))

    visit(root, ())
    return digest.hexdigest()
