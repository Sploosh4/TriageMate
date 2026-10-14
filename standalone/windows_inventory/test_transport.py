"""No live SSH in tests: exercise the actual process boundary with local children."""

import base64
import os
from pathlib import Path
import sys
import subprocess
import time

import pytest

from .test_contract import BINDING
from .transport import _capture, command


def test_command_enforces_pinned_noninteractive_single_host(tmp_path):
    config = tmp_path / "config"
    config.write_text("Host synthetic-host\n")
    config.chmod(0o600)
    argv = command(config, "synthetic-host", BINDING)
    assert "StrictHostKeyChecking=yes" in argv
    assert "BatchMode=yes" in argv and "ForwardAgent=no" in argv
    assert "ClearAllForwardings=yes" in argv and "PermitLocalCommand=no" in argv
    bootstrap = base64.b64decode(argv[-1].split()[-1]).decode("utf-16-le")
    assert BINDING.machine_guid in bootstrap and BINDING.tenant_id in bootstrap
    assert BINDING.device_id in bootstrap
    assert "ReadToEnd" in bootstrap
    for invalid in ("-oProxyCommand=bad", "host;command", "host user", "user@host", ""):
        with pytest.raises(ValueError):
            command(config, invalid, BINDING)
    config.chmod(0o644)
    with pytest.raises(ValueError, match="owner-only"):
        command(config, "synthetic-host", BINDING)
    config.chmod(0o600)
    link = tmp_path / "linked"
    link.symlink_to(config)
    with pytest.raises(ValueError, match="regular file"):
        command(link, "synthetic-host", BINDING)


def test_output_is_disk_backed_and_closed_after_use():
    with _capture(
        [
            sys.executable,
            "-c",
            "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())",
        ],
        b"synthetic",
        timeout_seconds=3,
        cancelled=lambda: False,
    ) as (output, deadline):
        assert output.read() == b"synthetic" and deadline > time.monotonic()
        assert Path(f"/proc/self/fd/{output.fileno()}").exists()
    assert output.closed


@pytest.mark.parametrize("timeout", [0, -1, True, float("nan"), float("inf")])
def test_invalid_deadlines_rejected(timeout):
    with pytest.raises(ValueError, match="timeout"):
        with _capture([], b"", timeout_seconds=timeout, cancelled=lambda: False):
            pytest.fail("Invalid deadline accepted")


def test_failure_hides_stderr_and_never_yields_partial_output():
    with pytest.raises(ValueError, match="^Inventory SSH command failed$"):
        with _capture(
            [
                sys.executable,
                "-c",
                "import sys; print('partial'); sys.stderr.write('private-value'); sys.exit(1)",
            ],
            b"",
            timeout_seconds=3,
            cancelled=lambda: False,
        ):
            pytest.fail("Failed process published output")


@pytest.mark.parametrize("stop", ["timeout", "cancel"])
def test_timeout_and_cancellation_reap_child(tmp_path, stop):
    pid_file = tmp_path / "pid"
    code = "import os,sys,time; open(sys.argv[1],'w').write(str(os.getpid())); time.sleep(30)"
    started = time.monotonic()
    with pytest.raises((ValueError, TimeoutError), match="cancelled|timed out"):
        with _capture(
            [sys.executable, "-c", code, str(pid_file)],
            b"",
            timeout_seconds=0.3 if stop == "timeout" else 3,
            cancelled=lambda: stop == "cancel" and pid_file.exists(),
        ):
            pytest.fail("Stopped process published output")
    assert time.monotonic() - started < 2
    pid = int(pid_file.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_supervisor_hard_exit_cannot_leave_inventory_child_running(tmp_path):
    pid_file = tmp_path / "orphan-pid"
    code = """
import os,sys,threading
from standalone.windows_inventory.transport import _capture
child = "import os,sys,time; open(sys.argv[1],'w').write(str(os.getpid())); time.sleep(30)"
threading.Timer(0.5, lambda: os._exit(125)).start()
with _capture([sys.executable,'-c',child,sys.argv[1]], b'', timeout_seconds=20, cancelled=lambda: False):
    pass
"""
    parent = subprocess.run(
        [sys.executable, "-c", code, str(pid_file)],
        timeout=4,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert parent.returncode == 125 and pid_file.exists()
    pid = int(pid_file.read_text())
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        path = Path(f"/proc/{pid}/stat")
        if not path.exists():
            return
        # A killed child awaiting init's reap cannot execute or retain open files.
        if path.read_text().split(")", 1)[1].split()[0] == "Z":
            return
        time.sleep(0.02)
    pytest.fail("Inventory child remained running after supervisor hard exit")


def test_each_remote_invocation_has_separate_identity_and_finite_deadline(tmp_path):
    config = tmp_path / "config"
    config.write_text("Host synthetic-host\n")
    config.chmod(0o600)
    first = command(config, "synthetic-host", BINDING, timeout_seconds=2.2)
    second = command(config, "synthetic-host", BINDING, timeout_seconds=2.2)
    assert first[:-1] == second[:-1] and first[-1] != second[-1]
    bootstrap = base64.b64decode(first[-1].split()[-1]).decode("utf-16-le")
    assert "Start-Sleep -Seconds 3;" in bootstrap
    assert "[Environment]::Exit(124)" in bootstrap
    for invalid in (0, True, float("inf")):
        with pytest.raises(ValueError, match="timeout"):
            command(config, "synthetic-host", BINDING, timeout_seconds=invalid)


def test_remote_cleanup_runs_after_local_reaping_and_only_on_failure(tmp_path):
    pid_file = tmp_path / "pid"
    code = 'import os,sys,time; open(sys.argv[1],"w").write(str(os.getpid())); time.sleep(30)'
    cleaned = []

    def cleanup():
        with pytest.raises(ProcessLookupError):
            os.kill(int(pid_file.read_text()), 0)
        cleaned.append(True)

    with pytest.raises(TimeoutError):
        with _capture(
            [sys.executable, "-c", code, str(pid_file)],
            b"",
            timeout_seconds=0.3,
            cancelled=lambda: False,
            remote_cleanup=cleanup,
        ):
            pytest.fail("Expired collector published evidence")
    assert cleaned == [True]
    with _capture(
        [sys.executable, "-c", 'print("complete")'],
        b"",
        timeout_seconds=3,
        cancelled=lambda: False,
        remote_cleanup=cleanup,
    ):
        pass
    assert cleaned == [True]


def test_unreachable_remote_cleanup_is_bounded_and_keeps_original_failure(monkeypatch):
    from contextlib import contextmanager
    from . import transport

    calls = []

    @contextmanager
    def unreachable(argv, script, **kwargs):
        calls.append((argv, kwargs))
        raise TimeoutError("synthetic cleanup connection unavailable")
        yield

    monkeypatch.setattr(transport, "_capture", unreachable)
    identity = base64.b64encode(b"unique synthetic invocation").decode()
    assert (
        transport._stop_remote(
            ["ssh", "synthetic-host", "powershell -EncodedCommand " + identity]
        )
        is False
    )
    assert len(calls) == 1 and calls[0][1]["timeout_seconds"] == 10
    cleanup = base64.b64decode(calls[0][0][-1].split()[-1]).decode("utf-16-le")
    assert identity in cleanup and "CreationDate" in cleanup
    assert ".Ticks % 10" in cleanup and "$p.WaitForExit(2000)" in cleanup
    assert "$_.CreationDate.ToUniversalTime().Ticks" in cleanup
    with pytest.raises(ValueError, match="identity"):
        transport._stop_remote(["powershell -EncodedCommand invalid;injection"])
    assert len(calls) == 1
