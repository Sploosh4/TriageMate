#!/usr/bin/env bash
# Optional offline contributor test harness, never an application deployment.
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
# The public entry point enforces isolation; the internal entry rechecks it.
case "${1:-}" in
  run)
    if [[ $# == 2 && $2 == --allow-network && ${GITHUB_ACTIONS:-false} != true ]]; then
      : # Explicit manual diagnostic run; dependency installation stays disabled.
    elif [[ $# == 1 ]]; then
      exec python3.12 "$ROOT/scripts/ci_network.py" bash "$ROOT/scripts/native_ci.sh" --isolated "$@"
    else
      echo 'Downloads are allowed only during manual provisioning; network diagnostics require manual run --allow-network.' >&2; exit 2
    fi ;;
  verify)
    [[ $# == 1 ]] || exit 2
    exec python3.12 "$ROOT/scripts/ci_network.py" bash "$ROOT/scripts/native_ci.sh" --isolated "$@" ;;
  provision)
    [[ ${GITHUB_ACTIONS:-false} != true ]] || { echo 'Provisioning is manual only.' >&2; exit 1; }
    if [[ $# == 2 && $2 == --allow-downloads ]]; then
      : # Explicit manual opt-in; the offline cache attempts still run first.
    elif [[ $# == 1 ]]; then
      exec python3.12 "$ROOT/scripts/ci_network.py" bash "$ROOT/scripts/native_ci.sh" --isolated "$@"
    else
      echo 'Usage: provision [--allow-downloads]' >&2; exit 2
    fi ;;
  --isolated)
    shift
    python3.12 -c 'import sys; sys.path.insert(0, sys.argv[1]); from ci_network import isolated; sys.exit(0 if isolated() else 1)' "$ROOT/scripts" || {
      echo 'Offline entry requires enforced network isolation.' >&2; exit 1;
    }
    [[ $# == 1 && ( $1 == run || $1 == verify || $1 == provision ) ]] || exit 2 ;;
  *) echo 'Usage: native_ci.sh {run|verify|provision [--allow-downloads]}' >&2; exit 2 ;;
esac
CI_ENV=${TRIAGEMATE_CI_ENV:-${HOME}/.local/share/triagemate-ci}
export PATH="$PATH:/usr/lib/postgresql/16/bin"
cd "$ROOT"
fingerprint() {
  sha256sum pyproject.toml uv.lock package.json package-lock.json ui-engine/package.json ui-engine/package-lock.json | sha256sum | cut -d ' ' -f1
}
toolchain() {
  python3.12 -c 'import sys; assert sys.version_info[:2] == (3,12)'
  [[ $(node --version) == v24.* ]] || { echo 'Node 24 required' >&2; return 1; }
  for tool in uv flock psql npm initdb pg_ctl pg_dump pg_restore createdb; do
    command -v "$tool" >/dev/null || { echo "Required CI tool missing from PATH: $tool" >&2; return 1; }
  done
  [[ $(pg_dump --version) == *' 16.'* ]] || { echo 'PostgreSQL 16 required' >&2; return 1; }
}
uv_sync() {
  local -a links=()
  [[ ! -d "$CI_ENV/wheelhouse" ]] || links=(--find-links "$CI_ENV/wheelhouse")
  UV_PROJECT_ENVIRONMENT="$CI_ENV/venv" uv sync --locked --no-build --no-default-groups --group ci --python python3.12 "${links[@]}" "$@"
}
verify_dependencies() {
  [[ -f "$CI_ENV/fingerprint" && $(cat "$CI_ENV/fingerprint") == "$(fingerprint)" ]] || {
    echo 'Native CI dependencies missing or stale. Run provision manually.' >&2; return 1;
  }
  [[ -f "$CI_ENV/parser/libpg_query.so" && -x "$CI_ENV/browser/chrome" ]] || {
    echo "Retained parser/browser artifacts missing; prepare them explicitly." >&2; return 1;
  }
  uv_sync --offline --check || return 1
  [[ -d "$CI_ENV/ui-engine/node_modules" ]] || return 1
  (cd "$CI_ENV"; npm ls --all --offline >/dev/null) || return 1
  (cd "$CI_ENV/ui-engine"; npm ls --all --offline >/dev/null) || return 1
  python3.12 "$ROOT/scripts/ci_dependency_state.py" verify-current "$CI_ENV"
}
verify() {
  toolchain
  [[ -f "$CI_ENV/workspace" && $(cat "$CI_ENV/workspace") == "$ROOT" ]] || {
    echo 'This is not the provisioned persistent CI checkout.' >&2; return 1;
  }
  [[ -f "$CI_ENV/pg/PG_VERSION" && -d "$CI_ENV/socket" ]]
  verify_dependencies
}
link_modules() {
  local suffix
  for suffix in node_modules ui-engine/node_modules; do
    if [[ -e "$ROOT/$suffix" || -L "$ROOT/$suffix" ]]; then
      [[ $(readlink -f "$ROOT/$suffix") == "$CI_ENV/$suffix" ]] || {
        echo "Checkout already has a different $suffix; refusing to replace it." >&2; return 1;
      }
    else
      ln -s "$CI_ENV/$suffix" "$ROOT/$suffix"
    fi
  done
}
install_npm() {
  local source=$1 destination=$2 allow_downloads=${3:-}
  local cache restored=0
  local -a caches
  mkdir -p "$destination"
  cp "$source/package.json" "$source/package-lock.json" "$destination/"
  IFS=: read -r -a caches <<< "$(npm config get cache):${TRIAGEMATE_NPM_CACHES:-}"
  for cache in "${caches[@]}"; do
    [[ $restored == 0 ]] || break
    [[ -d "$cache" ]] || continue
    echo "Checking npm cache for $source: $cache"
    if npm install --prefix "$destination" --cache "$cache" --offline --no-audit --no-fund; then restored=1; break; fi
  done
  if [[ $restored == 0 ]]; then
    [[ "$allow_downloads" == --allow-downloads ]] || { echo 'npm cache miss; no download allowed.' >&2; return 1; }
    npm install --prefix "$destination" --prefer-offline --no-audit --no-fund
  fi
  python3.12 - "$source/package-lock.json" "$destination/package-lock.json" <<'LOCK'
import json,sys
from pathlib import Path
expected=json.loads(Path(sys.argv[1]).read_text())
actual=json.loads(Path(sys.argv[2]).read_text())
# npm may derive this display-only name from the installation directory.
expected.pop('name',None);actual.pop('name',None)
assert actual == expected, 'npm changed locked dependency data'
LOCK
  cp "$source/package-lock.json" "$destination/package-lock.json"
  (cd "$destination"; npm ls --all --offline >/dev/null)
}

provision() {
  [[ ${GITHUB_ACTIONS:-false} != true ]] || { echo 'Provisioning is manual only.' >&2; return 1; }
  toolchain
  command -v uv >/dev/null
  if [[ -f "$CI_ENV/workspace" && $(cat "$CI_ENV/workspace") != "$ROOT" ]]; then
    echo 'Refusing a second CI checkout. Use the previously provisioned checkout.' >&2; return 1
  fi
  mkdir -p "$CI_ENV"
  if [[ -f "$CI_ENV/installed-files.json" ]]; then
    python3.12 "$ROOT/scripts/ci_dependency_state.py" verify "$CI_ENV" || {
      echo 'Installed files failed integrity checks; refusing to trust or reseal them.' >&2; return 1;
    }
  fi
  if ! verify_dependencies; then
    rm -f "$CI_ENV/fingerprint" "$CI_ENV/installed-files.json"
    # Only inspect the user's package caches or explicitly supplied locations.
    # Let package managers validate artifacts instead of copying arbitrary binaries.
    local cache restored=0
    local -a caches
    if uv_sync --offline; then restored=1; fi
    IFS=: read -r -a caches <<< "$(uv cache dir):${TRIAGEMATE_UV_CACHES:-}"
    for cache in "${caches[@]}"; do
      [[ $restored == 0 ]] || break
      [[ -d "$cache" ]] || continue
      echo "Checking Python cache: $cache"
      if UV_CACHE_DIR="$cache" uv_sync --offline; then restored=1; break; fi
    done
    if [[ $restored == 0 ]]; then
      [[ ${2:-} == --allow-downloads ]] || { echo 'Python cache miss; no download allowed.' >&2; return 1; }
      uv_sync
    fi
    install_npm "$ROOT" "$CI_ENV" "${2:-}"
    install_npm "$ROOT/ui-engine" "$CI_ENV/ui-engine" "${2:-}"
    uv_sync --offline --check
    python3.12 "$ROOT/scripts/ci_dependency_state.py" record "$CI_ENV"
    fingerprint > "$CI_ENV/fingerprint"
  fi
  link_modules
  mkdir -p "$CI_ENV/socket" "$CI_ENV/tmp"
  chmod 700 "$CI_ENV/socket" "$CI_ENV/tmp"
  if [[ ! -f "$CI_ENV/pg/PG_VERSION" ]]; then
    initdb -D "$CI_ENV/pg" -U triagemate --auth-local=trust --auth-host=reject > "$CI_ENV/initdb.log"
  fi
  if ! pg_ctl -D "$CI_ENV/pg" status >/dev/null 2>&1; then
    : > "$CI_ENV/postgres.log"
    pg_ctl -D "$CI_ENV/pg" -l "$CI_ENV/postgres.log" -o "-k $CI_ENV/socket -c listen_addresses='' -c dynamic_shared_memory_type=mmap" -w start
  fi
  if ! psql -h "$CI_ENV/socket" -U triagemate -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='triagemate'" | grep -qx 1; then
    createdb -h "$CI_ENV/socket" -U triagemate triagemate
  fi
  pg_ctl -D "$CI_ENV/pg" -m fast -w stop
  printf '%s\n' "$ROOT" > "$CI_ENV/workspace"
}
run() (
  verify
  link_modules
  [[ $EUID != 0 ]] || { echo 'Run CI as the unprivileged runner user.' >&2; return 1; }
  local run_dir="$CI_ENV"
  cleanup() {
    local result=$?
    trap - EXIT INT TERM
    if [[ -f "$run_dir/pg/postmaster.pid" ]]; then
      if ! pg_ctl -D "$run_dir/pg" -m fast -w stop; then
        echo "PostgreSQL could not stop; retained $run_dir for inspection" >&2
        exit 1
      fi
    fi
    find "$run_dir/tmp" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
    exit "$result"
  }
  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  find "$run_dir/tmp" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
  export PATH="$CI_ENV/venv/bin:$PATH"
  export TMPDIR="$run_dir/tmp" TMP="$run_dir/tmp" TEMP="$run_dir/tmp"
  export DATABASE_URL= PUBLIC_INTELLIGENCE_TEST_DATABASE_URL= TRIAGEMATE_DB_PASSWORD=
  export TRIAGEMATE_DATABASE_TARGET="$CI_ENV/ui-postgresql-target.json"
  export TRIAGEMATE_PG_PARSER_LIBRARY="$CI_ENV/parser/libpg_query.so"
  export PLAYWRIGHT_CHROMIUM_EXECUTABLE="$CI_ENV/browser/chrome"
  export TINY_PYTHON="$CI_ENV/venv/bin/python"
  export UV_OFFLINE=1 PIP_NO_INDEX=1 npm_config_offline=true
  export HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 TRIAGEMATE_SKIP_DOTENV=true
  export XDG_CACHE_HOME="$run_dir/tmp/cache" npm_config_logs_dir="$run_dir/tmp/npm-logs"
  # Reopen the same cluster; never create a new cluster during CI.
  if ! pg_ctl -D "$run_dir/pg" status >/dev/null 2>&1; then
    : > "$run_dir/postgres.log"
    pg_ctl -D "$run_dir/pg" -l "$run_dir/postgres.log" -o "-k $run_dir/socket -c listen_addresses='' -c dynamic_shared_memory_type=mmap" -w start
  fi
  psql -h "$run_dir/socket" -U triagemate -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='triagemate'" | grep -qx 1 || {
    echo 'Retained test database missing; provision manually.' >&2; exit 1;
  }
  local test_database="postgresql://triagemate@/triagemate?host=$run_dir/socket"
  # Keep dynamic shared memory inside this retained test data directory. The
  # runner is not a system account: logind otherwise deletes POSIX IPC on logout.
  # Do not weaken the host RemoveIPC policy or silently reuse another mode.
  psql "$test_database" -tAc 'SHOW dynamic_shared_memory_type' | grep -qx mmap || {
    echo 'Retained CI PostgreSQL must use mmap dynamic shared memory; stop it before retrying.' >&2; return 1;
  }
  cd "$ROOT"
  # Preserve the prepared database and its authority signatures. Tests own their
  # synthetic transactions; a normal run does not reset or rebuild any schema.
  if [[ ${TRIAGEMATE_CI_TRACE_NETWORK:-0} == 1 ]]; then
    strace -f -qq -e trace=connect -s 128 -o "$CI_ENV/network-connect.log" bash "$ROOT/scripts/ci_checks.sh"
  else
    bash "$ROOT/scripts/ci_checks.sh"
  fi
  verify_dependencies
)
# Serialize manual provisioning and runs as well as GitHub jobs.
[[ "$CI_ENV" == /* && "$CI_ENV" != / && ! -L "$CI_ENV" ]] || { echo 'CI environment must be an absolute, non-symlink directory.' >&2; exit 1; }
for entry in tmp pg socket operation.lock ui-engine parser browser; do
  [[ ! -L "$CI_ENV/$entry" ]] || { echo "Refusing symlink in CI state: $entry" >&2; exit 1; }
done
case "$CI_ENV/" in "$ROOT/"*) echo 'CI dependencies must live outside the checkout.' >&2; exit 1 ;; esac
mkdir -p "$CI_ENV"
exec 9>"$CI_ENV/operation.lock"
flock -n 9 || { echo 'Another CI operation is active.' >&2; exit 1; }
case "${1:-}" in
  provision) provision "$@" ;;
  verify) verify ;;
  run) run ;;
  *) echo "Usage: $0 {provision [--allow-downloads]|verify|run}" >&2; exit 2 ;;
esac
