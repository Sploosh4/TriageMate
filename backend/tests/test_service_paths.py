"""Service paths preserve explicit overrides without fallback, creation or scheduling."""

from dataclasses import FrozenInstanceError
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from backend.configuration.paths import load_paths
from backend.configuration.service_paths import (
    legacy_service_paths,
    service_paths,
    startup_service_paths,
)


def configured(tmp_path):
    return load_paths(
        {"TRIAGEMATE_RUNTIME_DIR": str(tmp_path / "runtime")}, home=tmp_path
    )


def test_configured_locations_are_independent_of_checkout_and_do_not_create_data(
    tmp_path,
):
    paths = configured(tmp_path)
    selected = service_paths(paths, {})
    assert selected.workspace_state == paths.state / "local-sql"
    assert selected.page == paths.workspace / "page.md"
    assert selected.shutdown_runs == paths.state / "shutdown"
    assert selected.shutdown_run is None
    assert selected.operations_config is None
    assert selected.operations_key == "local"
    assert list(tmp_path.iterdir()) == []
    with pytest.raises(FrozenInstanceError):
        selected.page = tmp_path / "other"


def test_legacy_adapter_is_explicit_and_preserves_current_defaults(tmp_path):
    selected = legacy_service_paths(tmp_path, {})
    assert selected.workspace_state == tmp_path / "ui-engine/work/local-sql"
    assert selected.page == tmp_path / "docs/ui/pages/page.md"
    assert selected.shutdown_runs == selected.workspace_state / "shutdown"
    assert not selected.page.exists()


@pytest.mark.parametrize("legacy", [False, True])
def test_explicit_overrides_are_preserved_in_both_layouts(tmp_path, legacy):
    env = {
        "TINY_STATE_DIR": str(tmp_path / "custom state"),
        "TINY_PAGE_PATH": str(tmp_path / "custom pages/selected.md"),
        "TINY_SHUTDOWN_DIR": str(tmp_path / "owned run"),
        "TRIAGEMATE_OPERATIONS_CONFIG": str(tmp_path / "operations.json"),
        "TRIAGEMATE_OPERATIONS_KEY": "synthetic-service",
    }
    selected = (
        legacy_service_paths(tmp_path, env)
        if legacy
        else service_paths(configured(tmp_path), env)
    )
    assert str(selected.workspace_state) == env["TINY_STATE_DIR"]
    assert str(selected.page) == env["TINY_PAGE_PATH"]
    assert str(selected.shutdown_run) == env["TINY_SHUTDOWN_DIR"]
    assert str(selected.operations_config) == env["TRIAGEMATE_OPERATIONS_CONFIG"]
    assert selected.operations_key == "synthetic-service"
    assert selected.shutdown_runs == selected.workspace_state / "shutdown"


@pytest.mark.parametrize(
    "name",
    [
        "TINY_STATE_DIR",
        "TINY_PAGE_PATH",
        "TINY_SHUTDOWN_DIR",
        "TRIAGEMATE_OPERATIONS_CONFIG",
    ],
)
@pytest.mark.parametrize("value", ["relative", "/tmp/../elsewhere", "/tmp/nul\0path"])
def test_invalid_explicit_location_never_falls_back(tmp_path, name, value):
    with pytest.raises(ValueError, match="absolute path"):
        service_paths(configured(tmp_path), {name: value})


def test_existing_operations_file_does_not_activate_scheduling(tmp_path):
    paths = configured(tmp_path)
    paths.config.mkdir(parents=True)
    (paths.config / "operations.json").write_text('{"synthetic":true}')
    selected = service_paths(paths, {})
    assert selected.operations_config is None
    assert (
        service_paths(
            paths, {"TRIAGEMATE_OPERATIONS_CONFIG": "", "TINY_SHUTDOWN_DIR": ""}
        ).shutdown_run
        is None
    )


def prepared_environment(tmp_path):
    env = {"TRIAGEMATE_STORAGE_LAYOUT": "configured"}
    for name in ("CONFIG", "DATA", "STATE", "CACHE", "RUNTIME", "WORKSPACE"):
        path = tmp_path / name.lower()
        path.mkdir(mode=0o700)
        env[f"TRIAGEMATE_{name}_DIR"] = str(path)
    paths = load_paths(env)
    (paths.state / "local-sql").mkdir(mode=0o700)
    (paths.state / "shutdown").mkdir(mode=0o700)
    return env


def test_startup_preserves_legacy_until_explicit_transition(tmp_path):
    assert startup_service_paths(tmp_path, {}) == legacy_service_paths(tmp_path, {})
    assert list(tmp_path.iterdir()) == []


def test_configured_startup_uses_verified_directories_without_scheduling(tmp_path):
    env = prepared_environment(tmp_path)
    selected = startup_service_paths(tmp_path / "unrelated-checkout", env)
    assert selected.page == tmp_path / "workspace/page.md"
    assert selected.workspace_state == tmp_path / "state/local-sql"
    assert selected.shutdown_runs == tmp_path / "state/shutdown"
    assert selected.operations_config is None
    assert not selected.page.exists()


@pytest.mark.parametrize("layout", ["", "invalid", "Configured"])
def test_unknown_layout_cannot_fall_back_or_create_storage(tmp_path, layout):
    with pytest.raises(ValueError, match="must be legacy or configured"):
        startup_service_paths(tmp_path, {"TRIAGEMATE_STORAGE_LAYOUT": layout})
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("damage", ["missing", "permissions", "symlink"])
def test_configured_startup_rejects_unavailable_storage_without_legacy_fallback(
    tmp_path, damage
):
    env = prepared_environment(tmp_path)
    workspace = tmp_path / "workspace"
    if damage == "permissions":
        workspace.chmod(0o755)
    else:
        workspace.rmdir()
        if damage == "symlink":
            workspace.symlink_to(tmp_path / "data", target_is_directory=True)
    with pytest.raises((ValueError, OSError)):
        startup_service_paths(tmp_path / "checkout", env)
    assert not (tmp_path / "checkout").exists()


def test_launcher_cli_matches_api_resolver_and_reports_invalid_layout(tmp_path):
    env = prepared_environment(tmp_path)
    command = [
        sys.executable,
        "-m",
        "backend.configuration.service_paths_cli",
        "--checkout",
        str(tmp_path / "checkout"),
    ]
    environment = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith(("TRIAGEMATE_", "TINY_"))
    } | env
    result = subprocess.run(
        command,
        cwd=Path(__file__).resolve().parents[2],
        env=environment,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)
    selected = startup_service_paths(tmp_path / "checkout", env)
    assert output["page"] == str(selected.page)
    assert output["shutdown_runs"] == str(selected.shutdown_runs)
    assert output["operations_config"] is None
    result = subprocess.run(
        command,
        cwd=Path(__file__).resolve().parents[2],
        env=environment | {"TRIAGEMATE_STORAGE_LAYOUT": "invalid"},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
    assert result.stdout == ""
    assert "must be legacy or configured" in result.stderr
