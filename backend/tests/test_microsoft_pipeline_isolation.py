"""Current collection must not require historical persistence even to import."""

import os
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _isolated(code):
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=ROOT,
        env={
            **os.environ,
            "PYTHONPATH": os.pathsep.join([str(ROOT / "backend"), str(ROOT)]),
            "TRIAGEMATE_SKIP_DOTENV": "true",
        },
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("prefix", ["microsoft_evidence", "backend.microsoft_evidence"])
def test_current_collection_imports_with_legacy_persistence_unavailable(prefix):
    _isolated(f'''
import importlib
import importlib.abc
import sys
from pathlib import Path

class BlockHistorical(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        # Sprint 3 replaces the retired flat database.py with this shared
        # package. The unqualified legacy import remains forbidden.
        if fullname == "backend.database" or fullname.startswith("backend.database."):
            return None
        forbidden = {{"database", "database_postgres", "risk_engine", "auth", "main",
                     "postgres_history", "baseline_collection", "retention_recovery",
                     "directory_device_reads", "projection_history"}}
        local = fullname.removeprefix("backend.")
        parts = local.split(".")
        if parts[0] in forbidden or (parts[0] == "microsoft_evidence" and forbidden.intersection(parts[1:])):
            raise AssertionError("Current collector tried to load " + fullname)

sys.meta_path.insert(0, BlockHistorical())
for name in ("collector_command", "pipeline", "software_pipeline", "missing_patch_pipeline",
             "antivirus_pipeline", "update_report_pipeline", "intune_report_transport"):
    importlib.import_module("{prefix}." + name)
shared = importlib.import_module("backend.database")
assert Path(shared.__file__).resolve() == Path.cwd() / "backend/database/__init__.py"
for name in ("database", "backend.database_postgres", "{prefix}.postgres_history"):
    try:
        importlib.import_module(name)
    except AssertionError as error:
        assert "Current collector tried to load " + name == str(error)
    else:
        raise AssertionError("Retired persistence import escaped the guard: " + name)
''')


def test_retired_api_and_store_modules_are_absent():
    for name in (
        "main.py",
        "auth.py",
        "database.py",
        "microsoft_evidence/postgres_history.py",
        "microsoft_evidence/baseline_collection.py",
    ):
        assert not (ROOT / "backend" / name).exists()
