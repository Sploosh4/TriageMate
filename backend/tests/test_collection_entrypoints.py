"""Existing collection command paths retain help and argument-error behavior."""

from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
COMMANDS = (
    "catalog_collection",
    "cve_repository",
    "github_dispatch",
    "github_scan",
    "osv_query_collection",
    "public_collection",
    "redhat_collection",
)


@pytest.mark.parametrize("name", COMMANDS)
@pytest.mark.parametrize("argument,expected", [("--help", 0), ("--no-such-option", 2)])
def test_established_launcher_matches_collection_command(name, argument, expected):
    results = [
        subprocess.run(
            [
                sys.executable,
                "-m",
                "standalone.evidence_pipeline." + prefix + name,
                argument,
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        for prefix in ("", "collection.")
    ]
    assert [result.returncode for result in results] == [expected, expected]
    assert results[0].stdout == results[1].stdout
    assert results[0].stderr == results[1].stderr
