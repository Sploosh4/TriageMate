"""Local OS-held worker leases fence restart races without guessing from PIDs."""

import fcntl
import os
from pathlib import Path
import stat
import threading

from standalone.evidence_pipeline.contracts import identifier
from standalone.evidence_pipeline.collection.snapshot_bundle import (
    _private_directory,
    _read,
    _write,
)


class Lease:
    def __init__(self, path):
        self.path = Path(path)
        _private_directory(self.path.parent)
        self.descriptor = None

    def acquire(self):
        if self.descriptor is not None:
            return True
        descriptor = os.open(
            self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600
        )
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_mode & 0o077
            ):
                raise ValueError("Worker lease must be an owner-only regular file")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                os.close(descriptor)
                return False
        except BaseException:
            os.close(descriptor)
            raise
        self.descriptor = descriptor
        return True

    def close(self):
        if self.descriptor is not None:
            os.close(self.descriptor)
            self.descriptor = None

    def __enter__(self):
        if not self.acquire():
            raise ValueError("Worker lease is already held")
        return self

    def __exit__(self, *args):
        self.close()


def paths(root, run_id):
    run_id = identifier(run_id)
    root = Path(root)
    _private_directory(root)
    return root / (run_id + ".lease"), root / (run_id + ".cancel")


class RecoveredHandle:
    def __init__(self, root, run_id):
        lease, self.cancel_path = paths(root, run_id)
        self.lease = Lease(lease)
        self.run_id = identifier(run_id)

    def poll(self):
        # Keep the acquired lease until the supervisor commits completion. A
        # delayed child cannot start between this observation and that commit.
        return 0 if self.lease.acquire() else None

    def cancel(self):
        content = self.run_id.encode()
        try:
            _write(self.cancel_path, content)
        except FileExistsError:
            if _read(self.cancel_path, 128) != content:
                raise ValueError("Worker cancellation identity differs") from None

    def close(self):
        self.lease.close()


def watch_cancellation(root, run_id):
    _, cancel = paths(root, run_id)
    stop = threading.Event()

    def monitor():
        while not stop.wait(0.1):
            try:
                if os.path.lexists(cancel) and _read(cancel, 128) == run_id.encode():
                    os._exit(125)
            except (OSError, ValueError):
                # An unsafe control artifact cannot be ignored while collecting.
                os._exit(126)

    thread = threading.Thread(target=monitor, daemon=True)
    thread.start()
    return stop, thread
