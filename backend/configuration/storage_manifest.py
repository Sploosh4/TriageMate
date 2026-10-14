"""Read-only, descriptor-bound evidence/workspace manifests for recoverable copying."""

from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat

from .paths import absolute_path

_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


@dataclass(frozen=True)
class FileRecord:
    path: str
    size: int
    sha256: str
    mtime_ns: int
    executable: bool


@dataclass(frozen=True)
class RetainedDirectory:
    """A named original left in place, not traversed or included in copied bytes."""

    path: str
    device: int
    inode: int
    mode: int
    mtime_ns: int


@dataclass(frozen=True)
class StorageManifest:
    directories: tuple[str, ...]
    files: tuple[FileRecord, ...]
    retained_directories: tuple[RetainedDirectory, ...] = ()

    @property
    def byte_count(self) -> int:
        return sum(record.size for record in self.files)

    def json_bytes(self) -> bytes:
        """Contains relative filenames; receipts containing lab names stay private."""
        return json.dumps(
            {"format": "triagemate-storage-v1", **asdict(self)},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.json_bytes()).hexdigest()


def open_directory(path: Path) -> int:
    """Caller closes the descriptor; no path component may be a symlink."""
    absolute_path(str(path), "storage source")
    descriptor = os.open("/", _DIRECTORY_FLAGS)
    try:
        for part in path.parts[1:]:
            child = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _owned(info: os.stat_result) -> None:
    if info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise ValueError("Storage source must be owned and not writable by other users")


def _identity(info: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def inventory_directory(
    descriptor: int, *, retained_directories: tuple[str, ...] = ()
) -> StorageManifest:
    """Hash one tree without following links or changing source bytes or permissions.

    A receipt is valid only for this observation. Copy/activation must recheck the
    source and destination while application writers are drained. Access times may
    change when files are read; mtime and executable intent are retained explicitly.
    """
    directories: list[str] = []
    files: list[FileRecord] = []
    retained: list[RetainedDirectory] = []
    if not isinstance(retained_directories, tuple) or any(
        not isinstance(value, str)
        or not value
        or value == "."
        or "\0" in value
        or PurePosixPath(value).is_absolute()
        or ".." in PurePosixPath(value).parts
        or str(PurePosixPath(value)) != value
        for value in retained_directories
    ):
        raise ValueError("Retained directories require exact relative paths")
    selected = set(retained_directories)
    if len(selected) != len(retained_directories) or any(
        any(str(parent) in selected for parent in PurePosixPath(value).parents)
        for value in selected
    ):
        raise ValueError("Retained directories must be unique and non-overlapping")

    def walk(directory: int, prefix: str) -> None:
        before = os.fstat(directory)
        _owned(before)
        if not stat.S_ISDIR(before.st_mode):
            raise ValueError("Storage source must be a directory")
        names = sorted(os.listdir(directory))
        for name in names:
            relative = prefix + name
            observed = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if relative in selected:
                if not stat.S_ISDIR(observed.st_mode) or observed.st_uid != os.getuid():
                    raise ValueError(
                        "A retained original must be an owned real directory"
                    )
                retained.append(
                    RetainedDirectory(
                        relative,
                        observed.st_dev,
                        observed.st_ino,
                        stat.S_IMODE(observed.st_mode),
                        observed.st_mtime_ns,
                    )
                )
                continue
            if not stat.S_ISDIR(observed.st_mode) and not (
                stat.S_ISREG(observed.st_mode) and observed.st_nlink == 1
            ):
                raise ValueError("Storage source cannot contain links or special files")
            _owned(observed)
            if stat.S_ISDIR(observed.st_mode):
                child = os.open(name, _DIRECTORY_FLAGS, dir_fd=directory)
                try:
                    if _identity(os.fstat(child)) != _identity(observed):
                        raise ValueError("Storage directory changed while opening")
                    directories.append(relative)
                    walk(child, relative + "/")
                finally:
                    os.close(child)
            elif stat.S_ISREG(observed.st_mode) and observed.st_nlink == 1:
                child = os.open(name, _FILE_FLAGS, dir_fd=directory)
                try:
                    initial = os.fstat(child)
                    _owned(initial)
                    if _identity(initial) != _identity(observed):
                        raise ValueError("Storage file changed while opening")
                    digest = hashlib.sha256()
                    size = 0
                    remaining = initial.st_size + 1
                    while remaining and (
                        block := os.read(child, min(remaining, 1024 * 1024))
                    ):
                        digest.update(block)
                        size += len(block)
                        remaining -= len(block)
                    if size != initial.st_size or _identity(
                        os.fstat(child)
                    ) != _identity(initial):
                        raise ValueError("Storage file changed while hashing")
                    files.append(
                        FileRecord(
                            relative,
                            size,
                            digest.hexdigest(),
                            initial.st_mtime_ns,
                            bool(initial.st_mode & stat.S_IXUSR),
                        )
                    )
                finally:
                    os.close(child)
            else:
                raise ValueError("Storage source cannot contain links or special files")
        if names != sorted(os.listdir(directory)) or _identity(
            os.fstat(directory)
        ) != _identity(before):
            raise ValueError("Storage directory changed while hashing")

    walk(descriptor, "")
    if {entry.path for entry in retained} != selected:
        raise ValueError("A selected retained directory does not exist")
    return StorageManifest(tuple(directories), tuple(files), tuple(retained))


def inventory_tree(
    source: Path, *, retained_directories: tuple[str, ...] = ()
) -> StorageManifest:
    descriptor = open_directory(source)
    try:
        return inventory_directory(
            descriptor, retained_directories=retained_directories
        )
    finally:
        os.close(descriptor)
