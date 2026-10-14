"""Explicit Ubuntu 24.04 CI browser prerequisites; never invoked by a test run."""

import argparse
import fcntl
import os
from pathlib import Path
import platform
import subprocess

PACKAGES = (
    "libatk1.0-0t64",
    "libatk-bridge2.0-0t64",
    "libcups2t64",
    "libasound2t64",
    "libgbm1",
    "libcairo2",
    "libpango-1.0-0",
    "libxcomposite1",
    "libxdamage1",
    "libxfixes3",
    "libxrandr2",
    "libatspi2.0-0t64",
    "fonts-liberation",
)
CI = Path("/home/runner/.local/share/triagemate-ci")


def install(*, allow_downloads, run=subprocess.run):
    command = ["apt-get", "install", "--no-install-recommends", "--no-remove", "-y"]
    environment = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
    result = run([*command, "--no-download", *PACKAGES], env=environment, check=False)
    if result.returncode == 0:
        return
    if not allow_downloads:
        raise RuntimeError(
            "Browser package cache miss or install failure; downloads require --allow-downloads"
        )
    run([*command, *PACKAGES], env=environment, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-downloads", action="store_true")
    args = parser.parse_args()
    system = platform.freedesktop_os_release()
    if (
        os.geteuid() != 0
        or system.get("ID") != "ubuntu"
        or system.get("VERSION_ID") != "24.04"
    ):
        raise SystemExit(
            "Use the host administration channel for the Ubuntu 24.04 CI VM"
        )
    if not (CI / "workspace").is_file() or not (CI / "pg/PG_VERSION").is_file():
        raise SystemExit("Existing native CI environment required")
    with os.fdopen(
        os.open(CI / "operation.lock", os.O_RDWR | os.O_NOFOLLOW), "r+"
    ) as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        install(allow_downloads=args.allow_downloads)


if __name__ == "__main__":
    main()
