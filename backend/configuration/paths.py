"""Single-user Linux path selection; resolution never creates or relocates data."""

from collections.abc import Mapping
from dataclasses import dataclass
import os
from pathlib import Path
import stat
from typing import Literal


@dataclass(frozen=True)
class ApplicationPaths:
    config: Path
    data: Path
    state: Path
    cache: Path
    runtime: Path
    workspace: Path

    @property
    def evidence(self) -> Path:
        return self.data / "evidence"

    @property
    def lab_evidence(self) -> Path:
        return self.evidence / "lab"

    @property
    def credentials(self) -> Path:
        return self.config / "credentials"


def absolute_path(value: str, name: str) -> Path:
    """Reject ambiguous application overrides rather than normalising them away."""
    path = Path(value)
    if not value or not path.is_absolute() or ".." in path.parts or "\0" in value:
        raise ValueError(f"{name} must be an absolute path without parent traversal")
    return path


def storage_layout(
    environment: Mapping[str, str] | None = None,
) -> Literal["legacy", "configured"]:
    """One explicit layout selection for services and independent database clients."""
    env = os.environ if environment is None else environment
    value = env.get("TRIAGEMATE_STORAGE_LAYOUT", "legacy")
    if value not in {"legacy", "configured"}:
        raise ValueError("TRIAGEMATE_STORAGE_LAYOUT must be legacy or configured")
    return "configured" if value == "configured" else "legacy"


def load_paths(
    environment: Mapping[str, str] | None = None, *, home: Path | None = None
) -> ApplicationPaths:
    """Application overrides win over XDG; invalid relative XDG values are ignored.

    Runtime storage must be explicitly available. Refusing startup without it is
    preferable to reusing a durable/shared fallback for locks after a reboot.
    The returned object is immutable and may be retained by the application.
    """
    env = os.environ if environment is None else environment
    base = absolute_path(str(Path.home() if home is None else home), "home")

    def selected(kind: str, xdg: str, default: Path) -> Path:
        override = env.get(f"TRIAGEMATE_{kind}_DIR")
        if override is not None:
            return absolute_path(override, f"TRIAGEMATE_{kind}_DIR")
        configured = env.get(xdg, "")
        parent = (
            absolute_path(configured, xdg)
            if configured and Path(configured).is_absolute()
            else default
        )
        return parent / "triagemate"

    config = selected("CONFIG", "XDG_CONFIG_HOME", base / ".config")
    data = selected("DATA", "XDG_DATA_HOME", base / ".local/share")
    state = selected("STATE", "XDG_STATE_HOME", base / ".local/state")
    cache = selected("CACHE", "XDG_CACHE_HOME", base / ".cache")
    runtime_override = env.get("TRIAGEMATE_RUNTIME_DIR")
    if runtime_override is not None:
        runtime = absolute_path(runtime_override, "TRIAGEMATE_RUNTIME_DIR")
    elif env.get("XDG_RUNTIME_DIR") and Path(env["XDG_RUNTIME_DIR"]).is_absolute():
        runtime = (
            absolute_path(env["XDG_RUNTIME_DIR"], "XDG_RUNTIME_DIR") / "triagemate"
        )
    else:
        raise ValueError(
            "Set XDG_RUNTIME_DIR or TRIAGEMATE_RUNTIME_DIR to an owned private runtime directory"
        )
    workspace_override = env.get("TRIAGEMATE_WORKSPACE_DIR")
    workspace = (
        absolute_path(workspace_override, "TRIAGEMATE_WORKSPACE_DIR")
        if workspace_override is not None
        else data / "workspace"
    )
    return ApplicationPaths(config, data, state, cache, runtime, workspace)


def validate_directory(path: Path, *, private: bool = True) -> None:
    """Check an existing destination without creating it or changing permissions.

    Call again at the explicit write/transition boundary; this check is not a
    substitute for descriptor-based safe creation by the storage owner.
    """
    absolute_path(str(path), "directory")
    for component in (*reversed(path.parents), path):
        if component.is_symlink():
            raise ValueError("Storage paths must not contain symlinks")
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError("Storage destination must be a directory")
    if info.st_uid != os.getuid():
        raise ValueError("Storage destination must be owned by the current user")
    if private and stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("Private storage destination must have mode 0700")
    if not os.access(path, os.W_OK | os.X_OK):
        raise ValueError("Storage destination must be writable and searchable")
