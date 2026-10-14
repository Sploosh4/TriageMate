"""Run the backend test suite with fixed, bounded parallelism."""

from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
from collections.abc import Mapping, Sequence


PARALLEL_WORKERS = 2
PARALLEL_THREAD_CAPS = {
    "MKL_NUM_THREADS": "1",
    "NUMEXPR_NUM_THREADS": "1",
    "OMP_NUM_THREADS": "1",
    "OPENBLAS_NUM_THREADS": "1",
}
XDIST_CONTROL_OPTIONS = (
    "-d",
    "-f",
    "-n",
    "--dist",
    "--loadscope-reorder",
    "--looponfail",
    "--max-worker-restart",
    "--maxprocesses",
    "--maxschedchunk",
    "--no-loadscope-reorder",
    "--numprocesses",
    "--px",
    "--tx",
)
XDIST_SHORT_CONTROL_OPTIONS = frozenset("dfn")
PYTEST_SHORT_FLAGS = frozenset("hVlvqsx")
PYTEST_SHORT_VALUE_OPTIONS = frozenset("Wckmopr")


def _inspect_short_option_cluster(argument: str) -> tuple[bool, bool]:
    """Return whether a short-option token conflicts or consumes the next token."""

    if len(argument) < 2 or not argument.startswith("-") or argument.startswith("--"):
        return False, False
    cluster = argument[1:]
    for index, option in enumerate(cluster):
        if option in XDIST_SHORT_CONTROL_OPTIONS:
            return True, False
        if option in PYTEST_SHORT_VALUE_OPTIONS:
            return False, index == len(cluster) - 1
        if option not in PYTEST_SHORT_FLAGS:
            return False, False
    return False, False


def _reject_xdist_control_options(pytest_args: Sequence[str]) -> None:
    conflicts = []
    consumes_next = False
    for argument in pytest_args:
        if consumes_next:
            consumes_next = False
            continue
        if argument == "--":
            break
        short_conflict, consumes_next = _inspect_short_option_cluster(argument)
        long_conflict = any(
            argument == option or argument.startswith(f"{option}=")
            for option in XDIST_CONTROL_OPTIONS
            if option.startswith("--")
        )
        if short_conflict or long_conflict:
            conflicts.append(argument)
    if conflicts:
        raise ValueError(
            "parallel worker and scheduling options are fixed; "
            "remove xdist worker or scheduling controls"
        )


def build_test_run(
    pytest_args: Sequence[str],
    *,
    source_environment: Mapping[str, str],
) -> tuple[list[str], dict[str, str]]:
    """Build one bounded two-worker pytest command and child environment."""

    command = [sys.executable, "-m", "pytest"]
    environment = dict(source_environment)
    _reject_xdist_control_options(pytest_args)
    try:
        environment_options = shlex.split(environment.get("PYTEST_ADDOPTS", ""))
    except ValueError as error:
        raise ValueError("PYTEST_ADDOPTS has invalid shell quoting") from error
    if "--" in environment_options:
        raise ValueError(
            "PYTEST_ADDOPTS cannot contain -- because it would precede the fixed "
            "worker controls"
        )
    _reject_xdist_control_options(environment_options)
    command.extend(["-n", str(PARALLEL_WORKERS), "--dist", "loadgroup"])
    environment.update(PARALLEL_THREAD_CAPS)
    command.extend(pytest_args or ("tests/",))
    return command, environment


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run backend tests with bounded pytest-xdist concurrency."
    )
    parser.add_argument(
        "--parallel",
        action="store_true",
        help="Deprecated compatibility flag; two-worker execution is always enabled.",
    )
    parser.add_argument(
        "--serial",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    options, pytest_args = parser.parse_known_args(argv)
    if options.serial:
        parser.error("serial execution is retired; use the fixed two-worker runner")
    if pytest_args[:1] == ["--"]:
        pytest_args = pytest_args[1:]
    try:
        command, environment = build_test_run(
            pytest_args,
            source_environment=os.environ,
        )
    except ValueError as error:
        parser.error(str(error))
    return subprocess.call(command, env=environment)


if __name__ == "__main__":
    raise SystemExit(main())
