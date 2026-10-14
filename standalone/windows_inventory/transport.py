"""Pinned SSH transport for the fixed read-only Windows inventory script."""

import base64
from contextlib import contextmanager
import math
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
from tempfile import TemporaryFile
import time
from uuid import uuid4

from .contract import DeviceBinding
from .staging import stage


def command(
    config: Path, host: str, expected: DeviceBinding, *, timeout_seconds=300
) -> list[str]:
    """No arbitrary remote command, interactive password or trust-on-first-use."""
    _timeout(timeout_seconds)
    config = Path(config)
    info = config.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_mode & 0o077
    ):
        raise ValueError("Inventory SSH config must be an owner-only regular file")
    if not isinstance(host, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", host
    ):
        raise ValueError("Inventory requires one explicit SSH host alias")
    if not isinstance(expected, DeviceBinding):
        raise ValueError("Inventory requires an explicit device binding")
    # Script is supplied on stdin, avoiding Windows command-line length limits
    # and remote temporary files. The only substitutions are validated GUIDs.
    # A per-invocation marker distinguishes this process from concurrent work.
    # The in-process runspace is an absolute remote deadline even when the SSH
    # client/host disappears and a separate cleanup connection is impossible.
    bootstrap = (
        f"$null='triagemate-inventory-{uuid4()}'; "
        "$w=[powershell]::Create(); "
        f"[void]$w.AddScript('Start-Sleep -Seconds {math.ceil(timeout_seconds)}; [Environment]::Exit(124)'); "
        "$null=$w.BeginInvoke(); try { "
        "$ErrorActionPreference='Stop'; "
        "[Console]::InputEncoding=[System.Text.UTF8Encoding]::new($false); "
        "$s=[Console]::In.ReadToEnd(); & ([ScriptBlock]::Create($s)) "
        f"-ExpectedMachineGuid '{expected.machine_guid}' "
        f"-ExpectedTenantId '{expected.tenant_id}' "
        f"-ExpectedDeviceId '{expected.device_id}'"
        " } finally { $w.Stop(); $w.Dispose() }"
    )
    encoded = base64.b64encode(bootstrap.encode("utf-16-le")).decode("ascii")
    return [
        "ssh",
        "-F",
        str(config.resolve()),
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "ClearAllForwardings=yes",
        "-o",
        "ForwardAgent=no",
        "-o",
        "PermitLocalCommand=no",
        "-o",
        "ControlMaster=no",
        "-o",
        "ControlPath=none",
        "-o",
        "ProxyCommand=none",
        "-o",
        "ProxyJump=none",
        "-o",
        "ConnectTimeout=15",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=2",
        host,
        "powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand " + encoded,
    ]


def _timeout(timeout_seconds):
    if (
        type(timeout_seconds) not in (int, float)
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
    ):
        raise ValueError("Inventory timeout must be positive and finite")


def _stop_remote(argv):
    """Stop only this uniquely marked invocation over the same pinned SSH host.

    Windows OpenSSH can retain its PowerShell descendants after a client closes.
    Match the complete encoded invocation, never a name or unqualified PID. A
    process handle and creation time check protect against process-ID reuse.
    The remote absolute deadline remains the fallback when connectivity is lost.
    """
    encoded = argv[-1].split()[-1]
    if not re.fullmatch(r"[A-Za-z0-9+/=]+", encoded):
        raise ValueError("Invalid inventory invocation identity")
    cleanup = (
        "$ErrorActionPreference='Stop'; "
        "Get-CimInstance Win32_Process -Filter \"Name='powershell.exe'\" | "
        f"Where-Object {{ $_.CommandLine -and $_.CommandLine.Contains('{encoded}') }} | "
        "ForEach-Object { "
        "$p=Get-Process -Id $_.ProcessId -ErrorAction SilentlyContinue; "
        "if ($p -and -not $p.HasExited -and "
        # CIM creation timestamps have microsecond precision; .NET StartTime
        # retains 100-nanosecond ticks. Compare at CIM precision, retaining the
        # exact encoded invocation and opened process handle as identity guards.
        "($p.StartTime.ToUniversalTime().Ticks - "
        "($p.StartTime.ToUniversalTime().Ticks % 10)) -eq "
        "$_.CreationDate.ToUniversalTime().Ticks) { "
        "try { $p.Kill(); if (-not $p.WaitForExit(2000)) { "
        "throw 'Inventory process did not stop' } "
        "} catch [System.InvalidOperationException] {} "
        "} }"
    )
    cleanup_encoded = base64.b64encode(cleanup.encode("utf-16-le")).decode("ascii")
    cleanup_argv = argv[:-1] + [
        "powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand "
        + cleanup_encoded
    ]
    try:
        with _capture(cleanup_argv, b"", timeout_seconds=10, cancelled=lambda: False):
            pass
        return True
    except (OSError, ValueError, TimeoutError):
        return False


@contextmanager
def _capture(argv, script, *, timeout_seconds, cancelled, remote_cleanup=None):
    _timeout(timeout_seconds)
    with (
        TemporaryFile() as output,
        TemporaryFile() as errors,
        TemporaryFile() as source,
    ):
        source.write(script)
        source.seek(0)
        if cancelled():
            raise ValueError("Inventory collection cancelled")
        deadline = time.monotonic() + timeout_seconds
        process = subprocess.Popen(
            [
                sys.executable,
                str(Path(__file__).with_name("child.py")),
                str(os.getpid()),
                *argv,
            ],
            stdin=source,
            stdout=output,
            stderr=errors,
            start_new_session=True,
        )
        group_stopped = False
        try:
            while process.poll() is None:
                if cancelled():
                    raise ValueError("Inventory collection cancelled")
                if time.monotonic() >= deadline:
                    raise TimeoutError("Inventory collection timed out")
                time.sleep(min(0.05, max(0, deadline - time.monotonic())))
            if cancelled():
                raise ValueError("Inventory collection cancelled")
            if time.monotonic() >= deadline:
                raise TimeoutError("Inventory collection timed out")
            if process.returncode != 0:
                # Provider stderr can include local identities. It is never
                # propagated into notifications, shared test logs or exceptions.
                raise ValueError("Inventory SSH command failed")
            # Stop helpers before exposing output so they cannot append during
            # validation after the SSH leader has exited successfully.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            group_stopped = True
            output.seek(0)
            yield output, deadline
        finally:
            # Also reap any descendants on success or interruption. The dedicated
            # session prevents signalling unrelated processes on the host.
            if not group_stopped:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            process.wait()
            if not group_stopped and remote_cleanup is not None:
                remote_cleanup()


@contextmanager
def collect(
    config: Path,
    host: str,
    expected: DeviceBinding,
    *,
    timeout_seconds=300,
    cancelled=lambda: False,
):
    """Yield only completely validated output, with one end-to-end deadline.

    Cancellation stops local SSH, then allows up to ten seconds for exact remote
    cleanup. A remote in-process deadline also survives abrupt client exit. No
    persistent remote job is created; the fixed command only reads inventory.
    The caller owns the
    durable evidence transaction and must separately record collection failures.
    """
    argv = command(config, host, expected, timeout_seconds=timeout_seconds)
    script = Path(__file__).with_name("collect.ps1").read_bytes()
    with _capture(
        argv,
        script,
        timeout_seconds=timeout_seconds,
        cancelled=cancelled,
        remote_cleanup=lambda: _stop_remote(argv),
    ) as (output, deadline):

        def interrupted():
            if time.monotonic() >= deadline:
                raise TimeoutError("Inventory collection timed out")
            return cancelled()

        with stage(output, expected, cancelled=interrupted) as staged:
            yield staged
