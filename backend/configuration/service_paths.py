"""Shared service locations; resolving them never creates data or enables schedules."""

from collections.abc import Mapping
from dataclasses import dataclass
import os
from pathlib import Path

from .paths import (
    ApplicationPaths,
    absolute_path,
    load_paths,
    storage_layout,
    validate_directory,
)


@dataclass(frozen=True)
class ServicePaths:
    workspace_state: Path
    page: Path
    shutdown_runs: Path
    shutdown_run: Path | None
    operations_config: Path | None
    operations_key: str


def _resolve(
    *, state: Path, page: Path, shutdown_runs: Path, environment: Mapping[str, str]
) -> ServicePaths:
    def selected(name: str, default: Path) -> Path:
        value = environment.get(name)
        return default if value is None else absolute_path(value, name)

    workspace_state = selected("TINY_STATE_DIR", state)
    selected_page = selected("TINY_PAGE_PATH", page)
    # Retain the existing explicit state override's shutdown-receipt location.
    runs = (
        workspace_state / "shutdown"
        if "TINY_STATE_DIR" in environment
        else shutdown_runs
    )
    shutdown = environment.get("TINY_SHUTDOWN_DIR")
    operations = environment.get("TRIAGEMATE_OPERATIONS_CONFIG")
    return ServicePaths(
        workspace_state,
        selected_page,
        runs,
        absolute_path(shutdown, "TINY_SHUTDOWN_DIR") if shutdown else None,
        absolute_path(operations, "TRIAGEMATE_OPERATIONS_CONFIG")
        if operations
        else None,
        environment.get("TRIAGEMATE_OPERATIONS_KEY", "local"),
    )


def service_paths(
    paths: ApplicationPaths, environment: Mapping[str, str] | None = None
) -> ServicePaths:
    """Resolve the configured layout, retaining established explicit service overrides.

    Operations require an explicit configuration reference, even if a file named
    operations.json exists in the configuration directory. A shutdown run is
    selected by the owning launcher, not invented or activated during resolution.
    """
    return _resolve(
        state=paths.state / "local-sql",
        page=paths.workspace / "page.md",
        shutdown_runs=paths.state / "shutdown",
        environment=os.environ if environment is None else environment,
    )


def legacy_service_paths(
    checkout: Path, environment: Mapping[str, str] | None = None
) -> ServicePaths:
    """Explicit transition adapter for the retained pre-relocation installation.

    Callers must choose this adapter deliberately until copy/replay verification
    and configuration activation are complete. It is not an automatic fallback
    from an unavailable configured destination.
    """
    absolute_path(str(checkout), "checkout")
    state = checkout / "ui-engine/work/local-sql"
    return _resolve(
        state=state,
        page=checkout / "docs/ui/pages/page.md",
        shutdown_runs=state / "shutdown",
        environment=os.environ if environment is None else environment,
    )


def startup_service_paths(
    checkout: Path, environment: Mapping[str, str] | None = None
) -> ServicePaths:
    """Select an explicit layout without activating or migrating any storage.

    The retained installation stays on its legacy layout until verified copying
    and activation select ``configured``. An invalid configured layout never
    falls back to the checkout. Provisioning remains a separate explicit action.
    """
    env = os.environ if environment is None else environment
    layout = storage_layout(env)
    if layout == "legacy":
        return legacy_service_paths(checkout, env)
    paths = load_paths(env)
    selected = service_paths(paths, env)
    for directory in {
        paths.config,
        paths.data,
        paths.state,
        paths.cache,
        paths.runtime,
        paths.workspace,
        selected.workspace_state,
        selected.page.parent,
        selected.shutdown_runs,
    }:
        validate_directory(directory)
    return selected
