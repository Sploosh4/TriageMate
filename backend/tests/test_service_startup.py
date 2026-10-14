"""Real FastAPI startup, refusal and restart in isolated synthetic storage."""

from contextlib import contextmanager
import http.client
import json
import os
from pathlib import Path
import socket
import signal
import subprocess
import sys
import time
from uuid import uuid4
import pytest

ROOT = Path(__file__).resolve().parents[2]


def unused_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def request(port, path, *, payload=None, token=None, expected=200):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        headers = {"Origin": f"http://127.0.0.1:{port}"}
        if payload is not None:
            headers.update({"Content-Type": "application/json", "X-Lab-Token": token})
        connection.request(
            "POST" if payload is not None else "GET",
            path,
            body=json.dumps(payload) if payload is not None else None,
            headers=headers,
        )
        response = connection.getresponse()
        body = json.loads(response.read())
        assert response.status == expected, body
        return body
    finally:
        connection.close()


@contextmanager
def running_service(env, output):
    port = unused_port()
    with output.open("w+") as log:
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "app.api:app",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
            ],
            cwd=ROOT,
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and process.poll() is None:
                try:
                    session = request(port, "/api/session")
                    break
                except (OSError, http.client.HTTPException):
                    time.sleep(0.02)
            else:
                pytest.fail("API did not start: " + output.read_text())
            yield port, session["token"]
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
                pytest.fail("API did not complete shutdown: " + output.read_text())
        assert process.returncode in (0, -signal.SIGTERM), output.read_text()
        assert "Application shutdown complete." in output.read_text()


def isolated_environment(tmp_path):
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("TINY_", "TRIAGEMATE_"))
    }
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    target = tmp_path / "database.json"
    target.write_text(
        json.dumps(
            dict(
                host="127.0.0.1",
                port=unused_port(),
                database="synthetic_unavailable",
                work=str(tmp_path / "absent-credentials"),
            )
        )
    )
    target.chmod(0o600)
    env.update(TRIAGEMATE_DATABASE_TARGET=str(target), TRIAGEMATE_STATE_DIR=str(state))
    return env, state


@pytest.mark.parametrize("legacy_override", [False, True])
def test_selected_state_survives_actual_api_restart(tmp_path, legacy_override):
    env, state = isolated_environment(tmp_path)
    obsolete = tmp_path / "obsolete-workspace"
    if legacy_override:
        env.update(
            TINY_STATE_DIR=str(obsolete), TINY_PAGE_PATH=str(obsolete / "page.md")
        )
    parser = os.environ.get("TRIAGEMATE_PG_PARSER_LIBRARY")
    if parser:
        env["TRIAGEMATE_PG_PARSER_LIBRARY"] = parser
    sentinel = state / "synthetic-state.json"
    sentinel.write_text(json.dumps({"revision": 1}))
    with running_service(env, tmp_path / "first.log") as (port, token):
        assert request(port, "/api/operations")["state"] == "unavailable"
        assert "error" in request(
            port,
            "/api/query",
            payload={"sql": "SELECT 1", "requestId": str(uuid4())},
            token=token,
            expected=503,
        )
        assert request(port, "/api/page", expected=404)["detail"] == "Not Found"
        assert (state / "operations").is_dir()
    sentinel.write_text(json.dumps({"revision": 2}))
    with running_service(env, tmp_path / "restart.log") as (port, token):
        assert request(port, "/api/pages", expected=404)["detail"] == "Not Found"
        assert request(port, "/api/operations")["state"] == "unavailable"
        assert json.loads(sentinel.read_text()) == {"revision": 2}
        assert "error" in request(
            port,
            "/api/query",
            payload={
                "sql": "DELETE FROM evidence.computers",
                "requestId": str(uuid4()),
            },
            token=token,
                expected=403,
        )
    assert not obsolete.exists()
    assert not (tmp_path / "absent-credentials").exists()


def test_copied_state_can_roll_back_without_losing_new_destination_edits(tmp_path):
    from backend.configuration.storage_copy import copy_tree_verified

    env, source = isolated_environment(tmp_path)
    sentinel = source / "synthetic-state.json"
    sentinel.write_text(json.dumps({"revision": 1}))
    sentinel.chmod(0o600)
    with running_service(env, tmp_path / "original.log") as (port, _):
        assert request(port, "/api/operations")["state"] == "unavailable"
    destination = tmp_path / "copied-state"
    copy_tree_verified(source, destination)
    copied = env | {"TRIAGEMATE_STATE_DIR": str(destination)}
    with running_service(copied, tmp_path / "copied.log") as (port, _):
        assert request(port, "/api/operations")["state"] == "unavailable"
        (destination / sentinel.name).write_text(json.dumps({"revision": 2}))
    with running_service(env, tmp_path / "rollback.log") as (port, _):
        assert request(port, "/api/operations")["state"] == "unavailable"
        assert json.loads(sentinel.read_text()) == {"revision": 1}
        assert json.loads((destination / sentinel.name).read_text()) == {"revision": 2}
    with running_service(copied, tmp_path / "return.log") as (port, _):
        assert request(port, "/api/operations")["state"] == "unavailable"
        assert json.loads((destination / sentinel.name).read_text()) == {"revision": 2}
    assert not (tmp_path / "absent-credentials").exists()
