"""Run the same installed convention tools locally, from hooks and in CI."""

from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    commands = (
        (sys.executable, "-m", "mypy", "--config-file", "pyproject.toml"),
        ("npm", "--prefix", "ui-engine", "run", "lint"),
        ("npm", "--prefix", "ui-engine", "run", "format:check"),
    )
    for command in commands:
        result = subprocess.run(command, cwd=ROOT, check=False)
        if result.returncode:
            return result.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
