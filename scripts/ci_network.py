"""Require a loopback-only network before executing offline CI commands."""

import json
import os
from pathlib import Path
import subprocess
import sys


def isolated():
    # Check the actual interfaces, not an environment flag. This also works
    # when the kernel forbids reading root's /proc/1 namespace descriptor.
    links = json.loads(
        subprocess.check_output(["/usr/sbin/ip", "-j", "link"], text=True)
    )
    return bool(links) and all(link["ifname"] == "lo" for link in links)


def main():
    command = sys.argv[1:]
    if not command:
        return 2
    if isolated():
        os.execvp(command[0], command)
    helper = Path("/usr/local/sbin/triagemate-ci-isolate")
    if (
        not helper.is_file()
        or helper.stat().st_uid != 0
        or helper.stat().st_mode & 0o022
    ):
        print(
            "Network isolation helper missing or unsafe; refusing online fallback.",
            file=sys.stderr,
        )
        return 1
    names = (
        "HOME",
        "PATH",
        "TRIAGEMATE_CI_ENV",
        "UV_CACHE_DIR",
        "npm_config_cache",
        "TRIAGEMATE_UV_CACHES",
        "TRIAGEMATE_NPM_CACHES",
        "GITHUB_ACTIONS",
        "TRIAGEMATE_CI_TRACE_NETWORK",
    )
    environment = [f"{name}={os.environ[name]}" for name in names if name in os.environ]
    os.execvp("sudo", ["sudo", "-n", str(helper), *environment, *command])


if __name__ == "__main__":
    raise SystemExit(main())
