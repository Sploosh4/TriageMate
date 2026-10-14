"""Path selection and rejection contracts without real evidence or services."""

from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from backend.configuration.paths import load_paths, validate_directory


def test_defaults_are_checkout_independent_and_do_not_create_files(
    tmp_path, monkeypatch
):
    home = tmp_path / "home"
    env = {"XDG_RUNTIME_DIR": str(tmp_path / "run")}
    first = load_paths(env, home=home)
    monkeypatch.chdir(tmp_path)
    assert load_paths(env, home=home) == first
    assert first.config == home / ".config/triagemate"
    assert first.evidence == home / ".local/share/triagemate/evidence"
    assert first.lab_evidence == first.evidence / "lab"
    assert first.state == home / ".local/state/triagemate"
    assert first.cache == home / ".cache/triagemate"
    assert first.runtime == tmp_path / "run/triagemate"
    assert first.workspace == first.data / "workspace"
    assert first.credentials == first.config / "credentials"
    assert list(tmp_path.iterdir()) == []
    with pytest.raises(FrozenInstanceError):
        first.data = Path("/other")


@pytest.mark.parametrize(
    "kind,xdg",
    [
        ("CONFIG", "CONFIG_HOME"),
        ("DATA", "DATA_HOME"),
        ("STATE", "STATE_HOME"),
        ("CACHE", "CACHE_HOME"),
    ],
)
def test_application_override_precedes_xdg(tmp_path, kind, xdg):
    env = {
        "XDG_RUNTIME_DIR": str(tmp_path / "run"),
        "XDG_" + xdg: str(tmp_path / "xdg"),
    }
    assert (
        getattr(load_paths(env, home=tmp_path), kind.lower())
        == tmp_path / "xdg/triagemate"
    )
    env[f"TRIAGEMATE_{kind}_DIR"] = str(tmp_path / "chosen")
    assert getattr(load_paths(env, home=tmp_path), kind.lower()) == tmp_path / "chosen"


@pytest.mark.parametrize(
    "value", ["", "relative", "../outside", "/tmp/../outside", "/tmp/invalid\0path"]
)
@pytest.mark.parametrize(
    "kind", ["CONFIG", "DATA", "STATE", "CACHE", "RUNTIME", "WORKSPACE"]
)
def test_invalid_explicit_overrides_fail(tmp_path, kind, value):
    with pytest.raises(ValueError):
        load_paths(
            {"XDG_RUNTIME_DIR": str(tmp_path / "run"), f"TRIAGEMATE_{kind}_DIR": value},
            home=tmp_path,
        )


def test_relative_xdg_values_use_defaults(tmp_path):
    paths = load_paths(
        {"XDG_RUNTIME_DIR": str(tmp_path / "run"), "XDG_DATA_HOME": "relative"},
        home=tmp_path,
    )
    assert paths.data == tmp_path / ".local/share/triagemate"


@pytest.mark.parametrize(
    "env", [{}, {"XDG_RUNTIME_DIR": ""}, {"XDG_RUNTIME_DIR": "relative"}]
)
def test_missing_runtime_requires_explicit_resolution(tmp_path, env):
    with pytest.raises(ValueError, match="runtime directory"):
        load_paths(env, home=tmp_path)


def test_explicit_workspace_and_runtime_are_independent_of_evidence(tmp_path):
    paths = load_paths(
        {
            "TRIAGEMATE_RUNTIME_DIR": str(tmp_path / "private-run"),
            "TRIAGEMATE_WORKSPACE_DIR": str(tmp_path / "notes"),
        },
        home=tmp_path,
    )
    assert paths.runtime == tmp_path / "private-run"
    assert paths.workspace == tmp_path / "notes"
    assert paths.workspace != paths.evidence


def test_private_directory_permissions_are_checked_not_repaired(tmp_path):
    destination = tmp_path / "evidence"
    destination.mkdir(mode=0o700)
    validate_directory(destination)
    destination.chmod(0o755)
    with pytest.raises(ValueError, match="0700"):
        validate_directory(destination)
    assert destination.stat().st_mode & 0o777 == 0o755


def test_symlink_ancestor_and_nondirectory_are_rejected(tmp_path):
    destination = tmp_path / "evidence"
    destination.mkdir(mode=0o700)
    alias = tmp_path / "alias"
    alias.symlink_to(destination, target_is_directory=True)
    for path in (alias, alias / "nested"):
        with pytest.raises(ValueError, match="symlinks"):
            validate_directory(path)
    file = tmp_path / "file"
    file.write_text("synthetic")
    with pytest.raises(ValueError, match="directory"):
        validate_directory(file)
    with pytest.raises(FileNotFoundError):
        validate_directory(tmp_path / "missing")


def test_foreign_owner_and_unwritable_directory_are_rejected(tmp_path, monkeypatch):
    import backend.configuration.paths as module

    tmp_path.chmod(0o700)
    actual = module.os.getuid()
    monkeypatch.setattr(module.os, "getuid", lambda: actual + 1)
    with pytest.raises(ValueError, match="owned"):
        validate_directory(tmp_path)
    monkeypatch.setattr(module.os, "getuid", lambda: actual)
    monkeypatch.setattr(module.os, "access", lambda *args: False)
    with pytest.raises(ValueError, match="writable"):
        validate_directory(tmp_path)
