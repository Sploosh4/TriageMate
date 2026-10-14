"""Owner-only saved payloads read incrementally with hash verification through EOF."""

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import stat


class VerifiedReader:
    def __init__(self, stream, cancelled):
        self.stream, self.cancelled = stream, cancelled
        self.digest = hashlib.sha256()

    def read(self, size):
        if type(size) is not int or size < 0:
            raise ValueError("Saved payload requires bounded reads")
        if self.cancelled():
            raise ValueError("Saved payload processing cancelled")
        value = self.stream.read(size)
        self.digest.update(value)
        return value


@dataclass(frozen=True)
class FilePayload:
    path: Path
    fingerprint: str

    def __post_init__(self):
        if (
            not isinstance(self.path, Path)
            or not self.path.is_absolute()
            or self.path.resolve() != self.path
            or not isinstance(self.fingerprint, str)
            or not re.fullmatch(r"[0-9a-f]{64}", self.fingerprint)
        ):
            raise ValueError("Saved payload requires an exact private path and SHA256")

    @contextmanager
    def open(self, *, cancelled=lambda: False):
        if self.path.resolve() != self.path:
            raise ValueError("Saved payload cannot traverse symlinks")
        descriptor = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            details = os.fstat(descriptor)
            if (
                not stat.S_ISREG(details.st_mode)
                or details.st_mode & 0o077
                or details.st_uid != os.getuid()
            ):
                raise ValueError("Saved payload requires an owner-only regular file")
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                reader = VerifiedReader(stream, cancelled)
                yield reader
                # A caller reading only a prefix must not bypass payload identity.
                while reader.read(65536):
                    pass
                after = os.fstat(descriptor)
                if (details.st_size, details.st_mtime_ns, details.st_ctime_ns) != (
                    after.st_size,
                    after.st_mtime_ns,
                    after.st_ctime_ns,
                ) or reader.digest.hexdigest() != self.fingerprint:
                    raise ValueError("Saved payload differs from its receipt")
        finally:
            os.close(descriptor)

    def verify(self):
        with self.open():
            pass
