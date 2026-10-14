"""Exec the inventory subprocess with Linux parent-death cancellation.

The supervisor may terminate its worker with os._exit, bypassing Python cleanup.
Set the kernel relationship in this fresh single-threaded child rather than an
unsafe preexec_fn in the multithreaded collection worker.
"""

import ctypes
import os
import signal
import sys


def main():
    if not sys.platform.startswith("linux") or len(sys.argv) < 3:
        raise SystemExit(125)
    expected_parent = int(sys.argv[1])
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
        raise SystemExit(125)
    # Cover the race where the parent exited before the relationship was set.
    if os.getppid() != expected_parent:
        raise SystemExit(125)
    os.execvp(sys.argv[2], sys.argv[2:])


if __name__ == "__main__":
    main()
