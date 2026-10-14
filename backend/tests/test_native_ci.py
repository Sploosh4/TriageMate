"""Native CI failure paths use an isolated checkout and fake installed tools."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import re

import yaml

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def lab(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "scripts").mkdir()
    shutil.copy(ROOT / "scripts/native_ci.sh", repo / "scripts/native_ci.sh")
    shutil.copy(
        ROOT / "scripts/ci_dependency_state.py", repo / "scripts/ci_dependency_state.py"
    )
    (repo / "scripts/ci_network.py").write_text(
        "import os, sys\ndef isolated(): return True\n"
        "if __name__ == '__main__': os.execvp(sys.argv[1], sys.argv[1:])\n"
    )
    shutil.copy(ROOT / "scripts/ci_checks.sh", repo / "scripts/ci_checks.sh")
    (repo / "backend").mkdir()
    (repo / "backend/placeholder").touch()
    (repo / "ui-engine").mkdir()
    for name in (
        "pyproject.toml",
        "uv.lock",
        "package.json",
        "package-lock.json",
        "ui-engine/package.json",
        "ui-engine/package-lock.json",
    ):
        (repo / name).write_text("{}\n")
    for args in (
        ["init", "-q"],
        ["add", "."],
        [
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "fixture",
        ],
    ):
        subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)
    installed = tmp_path / "installed"
    (installed / "venv/bin").mkdir(parents=True)
    (installed / "node_modules").mkdir()
    (installed / "parser").mkdir()
    (installed / "parser/libpg_query.so").write_bytes(b"synthetic parser")
    (installed / "browser").mkdir()
    (installed / "browser/chrome").write_text("synthetic browser")
    (installed / "browser/chrome").chmod(0o755)
    (installed / "ui-engine/node_modules").mkdir(parents=True)
    (installed / "workspace").write_text(str(repo) + "\n")
    (installed / "pg").mkdir()
    (installed / "pg/PG_VERSION").write_text("16")
    (installed / "socket").mkdir()
    (installed / "tmp").mkdir()
    bins = tmp_path / "bin"
    bins.mkdir()
    (bins / "python3.12").symlink_to(sys.executable)
    tool = """#!/bin/bash
set -eu
name=$(basename "$0")
printf '%s %s\\n' "$name" "$*" >> "$TRACE"
case "$name" in
node) echo v24.0.0 ;;
uv)
  if [[ "$*" == 'cache dir' ]]; then echo "$CACHE"; fi
  if [[ " $* " == *' --offline '* && " $* " != *' --check '* && "${CACHE_MISS:-0}" == 1 ]]; then exit 8; fi
  if [[ " $* " == *' --check '* && "${CHECK_FAIL:-0}" == 1 ]]; then exit 9; fi ;;

pg_dump) echo 'pg_dump (PostgreSQL) 16.0' ;;
initdb) mkdir -p "$2"; echo 16 > "$2/PG_VERSION" ;;
pg_ctl)
  if [[ " $* " == *' status '* ]]; then test -f "$2/postmaster.pid"; exit $?; fi
  if [[ " $* " == *' start '* ]]; then echo 999999 > "$2/postmaster.pid"; fi
  if [[ " $* " == *' stop '* ]]; then
    if [[ "${STOP_FAIL:-0}" == 1 ]]; then exit 1; fi
    rm -f "$2/postmaster.pid"
  fi ;;
psql)
  if [[ "$*" == *'SHOW dynamic_shared_memory_type'* ]]; then echo "${DSM_TYPE:-mmap}"; else echo 1; fi ;;

npm)
  if [[ "$1" == install ]]; then
    destination="$3"
    if [[ "$destination" == */ui-engine && " $* " == *' --offline '* && "${NPM_UI_CACHE_MISS:-0}" == 1 ]]; then exit 8; fi
    if [[ -n "${LOCK_REWRITE:-}" ]]; then printf '%s' "$LOCK_REWRITE" > "$destination/package-lock.json"; fi
  fi
  if [[ "$*" == "config get cache" ]]; then echo "$CACHE"; fi; if [[ " $* " == *' run '* && "${NPM_FAIL:-0}" == 1 ]]; then exit 17; fi ;;

esac
"""
    for name in (
        "uv",
        "psql",
        "node",
        "npm",
        "initdb",
        "pg_ctl",
        "pg_dump",
        "pg_restore",
        "createdb",
        "ruff",
    ):
        p = bins / name
        p.write_text(tool)
        p.chmod(0o755)
    p = installed / "venv/bin/python"
    p.write_text(tool)
    p.chmod(0o755)
    fingerprint = subprocess.check_output(
        "sha256sum pyproject.toml uv.lock package.json package-lock.json ui-engine/package.json ui-engine/package-lock.json | sha256sum",
        cwd=repo,
        shell=True,
        text=True,
    ).split()[0]
    (installed / "fingerprint").write_text(fingerprint + "\n")
    (tmp_path / "cache").mkdir()
    env = {
        **os.environ,
        "PATH": f"{bins}:{os.environ['PATH']}",
        "TRIAGEMATE_CI_TRACE_NETWORK": "0",
        "GITHUB_ACTIONS": "false",
        "TRIAGEMATE_CI_ENV": str(installed),
        "TRACE": str(tmp_path / "trace"),
        "CACHE": str(tmp_path / "cache"),
    }
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/ci_dependency_state.py"),
            "record",
            str(installed),
        ],
        check=True,
    )
    return repo, installed, env


def invoke(lab, action, **extra):
    repo, _, env = lab
    return subprocess.run(
        ["bash", "scripts/native_ci.sh", action],
        cwd=repo,
        env={**env, **extra},
        capture_output=True,
        text=True,
        timeout=20,
    )


def test_manual_provisioning_refuses_ci(lab):
    result = invoke(lab, "provision", GITHUB_ACTIONS="true")
    assert result.returncode != 0
    assert "manual only" in result.stderr
    assert not Path(lab[2]["TRACE"]).exists()


def test_matching_environment_is_accepted(lab):
    assert invoke(lab, "verify").returncode == 0


@pytest.mark.parametrize("missing", [False, True])
def test_missing_or_stale_dependencies_are_rejected(lab, missing):
    stamp = lab[1] / "fingerprint"
    if missing:
        stamp.unlink()
    else:
        stamp.write_text("stale")
    result = invoke(lab, "verify")
    assert result.returncode != 0
    assert "missing or stale" in result.stderr


@pytest.mark.parametrize("fail", ["0", "1"])
def test_run_reuses_workspace_database_and_cleans_only_temporary_files(lab, fail):
    (lab[1] / "tmp/stale").write_text("discard")
    result = invoke(lab, "run", NPM_FAIL=fail)
    assert result.returncode == (17 if fail == "1" else 0), result.stderr
    trace = Path(lab[2]["TRACE"]).read_text()
    assert "listen_addresses=''" in trace
    assert "-c dynamic_shared_memory_type=mmap" in trace
    assert "-m fast -w stop" in trace
    assert "initdb " not in trace
    assert "createdb " not in trace
    assert (lab[1] / "pg/PG_VERSION").exists()
    assert lab[0].exists()
    assert list((lab[1] / "tmp").iterdir()) == []


def test_repeated_runs_keep_same_database_and_workspace(lab):
    identity = (lab[1] / "pg/PG_VERSION").stat().st_ino
    for _ in range(2):
        result = invoke(lab, "run")
        assert result.returncode == 0, result.stderr
    assert (lab[1] / "pg/PG_VERSION").stat().st_ino == identity
    trace = Path(lab[2]["TRACE"]).read_text()
    assert "initdb " not in trace
    assert "npm install" not in trace


def test_corrupt_dependencies_are_rejected_without_download_or_reseal(lab):
    (lab[1] / "node_modules/changed").write_text("unexpected")
    result = invoke(lab, "verify")
    assert result.returncode != 0
    assert "files changed" in result.stderr
    result = invoke(lab, "provision")
    assert result.returncode != 0
    assert "refusing to trust" in result.stderr
    assert "npm install" not in Path(lab[2]["TRACE"]).read_text()


def test_second_checkout_is_rejected(lab):
    (lab[1] / "workspace").write_text("/another/workspace")
    assert invoke(lab, "run").returncode != 0
    assert invoke(lab, "provision").returncode != 0


def test_stop_failure_keeps_same_cluster(lab):
    result = invoke(lab, "run", NPM_FAIL="1", STOP_FAIL="1")
    assert result.returncode == 1
    assert "retained" in result.stderr
    assert (lab[1] / "pg/PG_VERSION").exists()


def assert_workflow_contract(text, tmp_path):
    workflow = yaml.load(text, Loader=yaml.BaseLoader)
    assert isinstance(workflow, dict)
    assert set(workflow["on"]) == {"pull_request", "push", "workflow_dispatch"}
    assert workflow["permissions"] == {"contents": "read"}
    job = workflow["jobs"]["containers"]
    assert job["runs-on"] == "ubuntu-latest"
    checkout, checks, start, logs, stop = job["steps"]
    assert re.fullmatch(r"actions/checkout@[0-9a-f]{40}", checkout["uses"])
    assert checkout["with"] == {"persist-credentials": "false"}
    assert logs["if"] == "failure()" and stop["if"] == "always()"
    assert "docker compose down -v" not in stop["run"]
    assert stop["run"].strip() == "docker compose down"
    for step in (checks, start):
        assert "if" not in step and "continue-on-error" not in step
        executable = [
            line.strip()
            for line in step["run"].splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        assert executable
    assert "docker build --target checks" in checks["run"]
    assert "docker run --rm triagemate-checks" in checks["run"]
    assert "docker compose up -d --build --wait" in start["run"]
    assert "curl --fail http://127.0.0.1:5190/api/health" in start["run"]
    assert "--services --status running" in start["run"]
    # Execute the real check step with synthetic tools; comments cannot pass.
    tool = tmp_path / "docker"
    tool.write_text(
        '#!/bin/sh\nprintf "%s\\n" "$*" >> "$TRACE"\nexit "${FAIL_DOCKER:-0}"\n'
    )
    tool.chmod(0o700)
    for failure in (0, 9):
        trace = tmp_path / ("trace-" + str(failure))
        result = subprocess.run(
            ["bash", "-e", "-o", "pipefail", "-c", checks["run"]],
            env={
                "PATH": str(tmp_path) + os.pathsep + os.defpath,
                "TRACE": str(trace),
                "FAIL_DOCKER": str(failure),
            },
            capture_output=True,
            text=True,
            timeout=5,
        )
        assert (result.returncode == 0) == (failure == 0)
        calls = trace.read_text().splitlines()
        assert calls[0] == "build --target checks -t triagemate-checks ."
        if failure == 0:
            assert calls[1] == "run --rm triagemate-checks"


def test_workflow_uses_pinned_checkout_and_two_container_validation(tmp_path):
    assert_workflow_contract((ROOT / ".github/workflows/ci.yml").read_text(), tmp_path)
    assert all(
        (ROOT / name).is_file()
        for name in ("Dockerfile", ".dockerignore", "compose.yaml")
    )


def test_workflow_comments_cannot_satisfy_structure(tmp_path):
    text = (ROOT / ".github/workflows/ci.yml").read_text()
    with pytest.raises(AssertionError):
        assert_workflow_contract(
            "\n".join("# " + line for line in text.splitlines()), tmp_path
        )


def test_comment_only_container_checks_are_rejected(tmp_path):
    workflow = yaml.load(
        (ROOT / ".github/workflows/ci.yml").read_text(), Loader=yaml.BaseLoader
    )
    step = workflow["jobs"]["containers"]["steps"][1]
    step["run"] = "\n".join("# " + line for line in step["run"].splitlines())
    with pytest.raises(AssertionError):
        assert_workflow_contract(yaml.safe_dump(workflow), tmp_path)


def test_runtime_configuration_remains_untracked():
    result = subprocess.run(
        ["git", "check-ignore", "--no-index", "backend/data/config/local.json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0


def test_secret_check_accepts_only_exact_negative_fixtures(tmp_path):
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "secret_check", ROOT / "scripts/check_secret_patterns.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    fake_key = "gh" + "p_abcdefghijklmnopqrstuvwxyz0123456789AB"
    assert module.PATTERN.search(fake_key)
    assert f'"{fake_key}",' in module.ALLOWED
    assert f'"{fake_key}extra",' not in module.ALLOWED


def test_provision_restores_from_cache_without_online_install(lab):
    (lab[1] / "fingerprint").unlink()
    result = invoke(lab, "provision")
    assert result.returncode == 0, result.stderr
    trace = Path(lab[2]["TRACE"]).read_text()
    installs = [
        line
        for line in trace.splitlines()
        if line.startswith(("uv sync", "npm install"))
    ]
    assert installs
    assert all("--offline" in line for line in installs)


def test_cache_miss_never_silently_downloads(lab):
    (lab[1] / "fingerprint").unlink()
    result = invoke(lab, "provision", CACHE_MISS="1")
    assert result.returncode != 0
    assert "no download allowed" in result.stderr
    trace = Path(lab[2]["TRACE"]).read_text()
    assert all(
        "--offline" in line for line in trace.splitlines() if line.startswith("uv sync")
    )


def test_dependency_version_check_failure_cannot_be_hidden_by_matching_file_stamp(lab):
    assert invoke(lab, "verify", CHECK_FAIL="1").returncode != 0


def test_symlinked_temporary_directory_is_rejected_without_deleting_target(
    lab, tmp_path
):
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "keep"
    sentinel.write_text("preserve")
    (lab[1] / "tmp").rmdir()
    (lab[1] / "tmp").symlink_to(outside, target_is_directory=True)
    result = invoke(lab, "run")
    assert result.returncode != 0
    assert "Refusing symlink" in result.stderr
    assert sentinel.read_text() == "preserve"


def test_run_cannot_accept_download_flag(lab):
    repo, _, env = lab
    result = subprocess.run(
        ["bash", "scripts/native_ci.sh", "run", "--allow-downloads"],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 2
    assert "only during manual provisioning" in result.stderr
    assert not Path(env["TRACE"]).exists()


@pytest.mark.parametrize("github", ["false", "true"])
def test_online_diagnostic_is_manual_and_never_installs(lab, github):
    repo, _, env = lab
    result = subprocess.run(
        ["bash", "scripts/native_ci.sh", "run", "--allow-network"],
        cwd=repo,
        env={**env, "GITHUB_ACTIONS": github},
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == (2 if github == "true" else 0), result.stderr
    trace = Path(env["TRACE"])
    if github == "true":
        assert not trace.exists()
    else:
        assert "npm install" not in trace.read_text()
        assert all(
            "--check" in line
            for line in trace.read_text().splitlines()
            if line.startswith("uv sync")
        )


@pytest.mark.parametrize(
    "rewrite,accepted",
    [(' {"name":"different-directory"}', True), ('{"packages":{"changed":{}}}', False)],
)
def test_provision_accepts_only_display_name_lock_changes(lab, rewrite, accepted):
    (lab[1] / "fingerprint").unlink()
    result = invoke(lab, "provision", LOCK_REWRITE=rewrite)
    assert (result.returncode == 0) == accepted, result.stderr
    if accepted:
        assert (lab[1] / "package-lock.json").read_text() == "{}\n"
    else:
        assert "npm changed locked dependency data" in result.stderr
        assert not (lab[1] / "fingerprint").exists()


@pytest.mark.parametrize("filename", ["package.json", "package-lock.json"])
def test_ui_dependency_changes_require_provisioning(lab, filename):
    (lab[0] / "ui-engine" / filename).write_text('{"changed": true}')
    assert invoke(lab, "verify").returncode != 0


def test_ui_installed_files_are_verified_before_provisioning(lab):
    (lab[1] / "ui-engine/node_modules/changed").write_text("unexpected")
    result = invoke(lab, "provision")
    assert result.returncode != 0
    assert "refusing to trust" in result.stderr
    assert "npm install" not in Path(lab[2]["TRACE"]).read_text()


def test_both_node_environments_are_retained_and_checked(lab):
    (lab[1] / "fingerprint").unlink()
    result = invoke(lab, "provision")
    assert result.returncode == 0, result.stderr
    trace = Path(lab[2]["TRACE"]).read_text()
    assert "--prefix " + str(lab[1] / "ui-engine") in trace
    assert (lab[0] / "ui-engine/node_modules").resolve() == lab[
        1
    ] / "ui-engine/node_modules"
    assert (lab[0] / "node_modules").resolve() == lab[1] / "node_modules"


def test_ui_npm_cache_miss_does_not_download(lab):
    (lab[1] / "fingerprint").unlink()
    result = invoke(lab, "provision", NPM_UI_CACHE_MISS="1")
    assert result.returncode != 0
    assert "npm cache miss; no download allowed" in result.stderr
    trace = Path(lab[2]["TRACE"]).read_text()
    assert all(
        "--offline" in line
        for line in trace.splitlines()
        if line.startswith("npm install")
    )
    assert not (lab[1] / "fingerprint").exists()


def test_ui_dependency_directory_cannot_redirect_provisioning(lab, tmp_path):
    shutil.rmtree(lab[1] / "ui-engine")
    outside = tmp_path / "outside"
    outside.mkdir()
    (lab[1] / "ui-engine").symlink_to(outside, target_is_directory=True)
    result = invoke(lab, "provision")
    assert result.returncode != 0
    assert "Refusing symlink" in result.stderr
    assert not list(outside.iterdir())


@pytest.mark.parametrize("corrupt", [False, True])
def test_old_inventory_is_verified_before_ui_upgrade(lab, corrupt):
    stamp = lab[1] / "installed-files.json"
    recorded = json.loads(stamp.read_text())["files"]
    stamp.write_text(
        json.dumps(
            {
                key: value
                for key, value in recorded.items()
                if not key.startswith(("ui-engine/", "parser/", "browser/"))
            }
        )
    )
    (lab[1] / "fingerprint").unlink()
    if corrupt:
        (lab[1] / "node_modules/changed").write_text("unexpected")
    result = invoke(lab, "provision")
    assert (result.returncode == 0) is not corrupt, result.stderr
    if corrupt:
        assert "refusing to trust" in result.stderr
        assert "version" not in json.loads(stamp.read_text())
    else:
        assert json.loads(stamp.read_text())["version"] == 3


def test_old_inventory_cannot_accept_current_run(lab):
    stamp = lab[1] / "installed-files.json"
    stamp.write_text(json.dumps(json.loads(stamp.read_text())["files"]))
    result = invoke(lab, "verify")
    assert result.returncode != 0
    assert "requires manual UI artifact upgrade" in result.stderr


@pytest.mark.parametrize("artifact", ["parser/libpg_query.so", "browser/chrome"])
def test_changed_native_ui_artifacts_are_not_resealed(lab, artifact):
    (lab[1] / artifact).write_text("changed")
    result = invoke(lab, "provision")
    assert result.returncode != 0
    assert "refusing to trust" in result.stderr


def test_v2_inventory_is_checked_before_artifact_upgrade(lab):
    stamp = lab[1] / "installed-files.json"
    recorded = json.loads(stamp.read_text())
    recorded["version"] = 2
    recorded["files"] = {
        key: value
        for key, value in recorded["files"].items()
        if not key.startswith(("parser/", "browser/"))
    }
    stamp.write_text(json.dumps(recorded))
    assert invoke(lab, "verify").returncode != 0
    assert invoke(lab, "provision").returncode == 0
    assert json.loads(stamp.read_text())["version"] == 3


def test_missing_tool_reports_the_tool_name(lab):
    bins = Path(lab[2]["PATH"].split(":")[0])
    (bins / "uv").unlink()
    result = invoke(lab, "verify", PATH=f"{bins}:/usr/bin:/bin")
    assert result.returncode != 0
    assert "Required CI tool missing from PATH: uv" in result.stderr


def test_run_preserves_prepared_schemas(lab):
    result = invoke(lab, "run")
    assert result.returncode == 0, result.stderr
    trace = Path(lab[2]["TRACE"]).read_text()
    assert "DROP SCHEMA" not in trace
    assert "CREATE SCHEMA" not in trace
    assert "python -m scripts.run_backend_tests tests/" in trace


def test_run_rejects_incompatible_shared_memory_before_resetting_tables(lab):
    result = invoke(lab, "run", DSM_TYPE="posix")
    assert result.returncode != 0
    assert "must use mmap dynamic shared memory" in result.stderr
    trace = Path(lab[2]["TRACE"]).read_text()
    assert "DROP SCHEMA" not in trace
    assert "-m fast -w stop" in trace
