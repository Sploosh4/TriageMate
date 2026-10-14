"""Own a temporary FastAPI server for browser tests on a synthetic target."""

from contextlib import closing
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
from tempfile import TemporaryDirectory
import time
from urllib.request import urlopen

from backend.database.connections import local_database
from backend.database.baseline.catalogue import fingerprint
from backend.database.schema import identify_layout, verify

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    # Browser tests must never be directed at an operator's retained evidence.
    database = local_database()
    with closing(database.connect()) as connection, connection.cursor() as cursor:
        verify(cursor)
        profile, _ = identify_layout(fingerprint(cursor))
        if profile not in {"synthetic", "runner"}:
            raise ValueError("Browser checks require an explicitly synthetic database")
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    with TemporaryDirectory(prefix="triagemate-browser-") as directory:
        state = Path(directory)
        state.chmod(0o700)
        url = f"http://127.0.0.1:{port}"
        environment = dict(
            os.environ,
            TRIAGEMATE_STATE_DIR=str(state),
            TRIAGEMATE_OPERATIONS_CONFIG="",
            TRIAGEMATE_TEST_URL=url,
        )
        log_path = state / "server.log"
        with log_path.open("w+") as log:
            server = subprocess.Popen(
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
                env=environment,
                stdout=log,
                stderr=subprocess.STDOUT,
            )
            try:
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline and server.poll() is None:
                    try:
                        with urlopen(url + "/api/health", timeout=1) as response:
                            if response.status == 200:
                                break
                    except OSError:
                        time.sleep(0.05)
                else:
                    raise RuntimeError(
                        "Owned browser-test server failed readiness: "
                        + log_path.read_text()
                    )
                result = subprocess.run(
                    ["npm", "--prefix", "ui-engine", "test", "--", "--workers=1"],
                    cwd=ROOT,
                    env=environment,
                    check=False,
                )
            finally:
                if server.poll() is None:
                    server.terminate()
                try:
                    server.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=5)
                    raise RuntimeError("Browser-test server failed to drain") from None
            if (
                server.returncode not in (0, -signal.SIGTERM)
                or "Application shutdown complete." not in log_path.read_text()
            ):
                raise RuntimeError(
                    "Browser-test server failed to drain: " + log_path.read_text()
                )
            return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
