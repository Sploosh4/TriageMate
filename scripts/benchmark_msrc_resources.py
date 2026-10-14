"""Measure synthetic MSRC imports or read-only retained-evidence verification.

Generated MSRC evidence is always rolled back.

Linux /proc samples cover this Python process, its PostgreSQL backend and the
associated cluster. Optional loopback HTTP exercises the transport read loop;
upstream TLS and UI rendering remain outside this benchmark.
"""

from pathlib import Path
from tempfile import TemporaryDirectory
from datetime import datetime, timezone
from uuid import uuid4
import argparse
import hashlib
import json
import os
import sys
import threading
import time
import base64
import stat

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from standalone.evidence_pipeline.contracts import SourceScope
from standalone.evidence_pipeline.file_payload import FilePayload
from standalone.evidence_pipeline.parsing.public_snapshot import PublicSnapshot
from standalone.evidence_pipeline.persistence.authority import authorize_connection
from standalone.evidence_pipeline.persistence.public_store import persist_public
from standalone.evidence_pipeline.runtime import local_database

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument(
    "--local-http",
    action="store_true",
    help="Stream the synthetic file through a loopback HTTP response before import",
)
parser.add_argument(
    "--verify-retained",
    action="store_true",
    help="Measure the complete retained-database verifier in a read-only transaction instead of importing a fixture",
)
parser.add_argument(
    "--profile",
    type=Path,
    help="Write a new local cProfile artifact (retained-verifier mode only)",
)
parser.add_argument("--records", type=int, default=100)
parser.add_argument("--note-bytes", type=int, default=0)
args = parser.parse_args()
if args.profile and not args.verify_retained:
    parser.error("--profile requires --verify-retained")
if args.verify_retained and (args.local_http or args.records != 100 or args.note_bytes):
    parser.error("Retained verification cannot also generate/import an MSRC fixture")
if args.profile and (args.profile.exists() or not args.profile.parent.is_dir()):
    parser.error("Profile requires a new file in an existing local directory")
n = args.records
note_bytes = args.note_bytes
if not (1 <= n <= 10000 and 0 <= note_bytes <= 64_000_000):
    parser.error(
        "Fixture generation requires 1..10000 records and 0..64000000 note bytes per record"
    )
# Linux getrusage can include a pre-exec RSS high-water mark. Reset/read
# this process's /proc watermark; sampled RSS/PSS remains reported separately.
Path("/proc/self/clear_refs").write_text("5")


def peak_rss_kib():
    return int(
        next(
            line.split()[1]
            for line in Path("/proc/self/status").read_text().splitlines()
            if line.startswith("VmHWM:")
        )
    )


metrics = {}
phase_metrics = {}
phase = "generation"
samples = 0
stop = threading.Event()
backend = None
postmaster = None


def process_parent(pid):
    return int(Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[1])


def memory(pid):
    fields = {
        line.split(":")[0]: int(line.split()[1])
        for line in Path(f"/proc/{pid}/smaps_rollup").read_text().splitlines()
        if line.startswith(("Rss:", "Pss:"))
    }
    return fields


def sample():
    global samples
    while not stop.is_set():
        try:
            observed_phase = phase
            own = memory(os.getpid())
            observed = {"python_rss_kib": own["Rss"], "python_pss_kib": own["Pss"]}
            if backend is not None:
                pg = memory(backend)
                observed["backend_rss_kib"] = pg["Rss"]
                observed["backend_pss_kib"] = pg["Pss"]
                observed["python_backend_pss_kib"] = own["Pss"] + pg["Pss"]
            if postmaster is not None:
                # The kernel already exposes direct children. Scanning every
                # host process each sample distorted the verifier measurement.
                children = (
                    Path(f"/proc/{postmaster}/task/{postmaster}/children")
                    .read_text()
                    .split()
                )
                pids = [postmaster, *(int(pid) for pid in children)]
                cluster = []
                for pid in pids:
                    try:
                        cluster.append(memory(pid)["Pss"])
                    except (FileNotFoundError, ProcessLookupError):
                        pass
                observed["postgres_cluster_pss_kib"] = sum(cluster)
                observed["python_cluster_pss_kib"] = own["Pss"] + sum(cluster)
            temporary_logical = temporary_allocated = 0
            seen_files = set()
            for fd in Path("/proc/self/fd").iterdir():
                try:
                    name = os.readlink(fd)
                    info = fd.stat()
                    identity = (info.st_dev, info.st_ino)
                    if (
                        name.endswith(" (deleted)")
                        and stat.S_ISREG(info.st_mode)
                        and identity not in seen_files
                    ):
                        seen_files.add(identity)
                        temporary_logical += info.st_size
                        temporary_allocated += info.st_blocks * 512
                except (FileNotFoundError, ProcessLookupError):
                    pass
            observed["temporary_logical_bytes"] = temporary_logical
            observed["temporary_allocated_bytes"] = temporary_allocated
            phase_peak = phase_metrics.setdefault(observed_phase, {})
            for k, v in observed.items():
                metrics[k] = max(metrics.get(k, 0), v)
                phase_peak[k] = max(phase_peak.get(k, 0), v)
            samples += 1
        except (OSError, KeyError, ValueError):
            metrics["sampling_incomplete"] = True
        stop.wait(0.1)


def local_http_copy(source, destination):
    import http.client
    import shutil
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from standalone.evidence_pipeline.collection.public_transport import read_complete

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            if self.path != "/synthetic-cvrf":
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Length", str(source.stat().st_size))
            self.end_headers()
            with source.open("rb") as stream:
                shutil.copyfileobj(stream, self.wfile, length=65536)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=30)
    try:
        connection.request("GET", "/synthetic-cvrf")
        response = connection.getresponse()
        assert response.status == 200
        with destination.open("xb") as output:
            destination.chmod(0o600)
            count = read_complete(
                response,
                deadline=time.monotonic() + 120,
                connection=connection,
                output=output,
            )
            output.flush()
            os.fsync(output.fileno())
        assert (
            count == source.stat().st_size == int(response.getheader("Content-Length"))
        )
    finally:
        connection.close()
        server.shutdown()
        server.server_close()
        worker.join(5)
    assert not worker.is_alive()


if args.verify_retained:
    from contextlib import closing
    import cProfile

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ui-engine/postgres"))
    from epss.baseline import verify

    phase = "retained_verifier"
    profiler = cProfile.Profile() if args.profile else None
    started = time.monotonic()
    observer = threading.Thread(target=sample)
    observer.start()
    counts = None
    failure = None
    try:
        with closing(local_database().connect()) as connection:
            connection.set_session(isolation_level="REPEATABLE READ", readonly=True)
            with connection, connection.cursor() as cursor:
                backend = connection.get_backend_pid()
                postmaster = process_parent(backend)
                counts = (
                    profiler.runcall(verify, cursor) if profiler else verify(cursor)
                )
    except BaseException as exc:
        failure = exc
    finally:
        backend = postmaster = None
        stop.set()
        observer.join()
    if profiler:
        # Exclusive creation keeps a local artifact from replacing an existing file.
        with args.profile.open("xb") as output:
            os.fchmod(output.fileno(), 0o600)
            import marshal

            profiler.create_stats()
            marshal.dump(profiler.stats, output)
    print(
        json.dumps(
            {
                "mode": "retained_verifier",
                "seconds": time.monotonic() - started,
                "peak_python_rss_kib": peak_rss_kib(),
                "memory": metrics,
                "samples": samples,
                "verified_counts": counts,
                "integrity_pass": failure is None,
                "error_type": None if failure is None else type(failure).__name__,
                "read_only": True,
                "profiled": profiler is not None,
                "measurement": "100ms samples; verifier plus associated PostgreSQL cluster PSS, including resident baseline and unrelated DB work; excludes UI/browser; anonymous temporary files counted once by inode; individual peaks may occur at different times",
            }
        ),
        flush=True,
    )
    if failure is not None:
        raise failure.with_traceback(failure.__traceback__)
    raise SystemExit(0)


scope = SourceScope(
    str(uuid4()),
    "MSRC",
    "security_updates",
    "synthetic-memory-first-insert",
    "synthetic",
    "TriageMate generated synthetic CVRF first-insert benchmark; transaction always rolled back",
)
run = str(uuid4())
phases = {}
counts = {}
functions = []
start = time.monotonic()
thread = threading.Thread(target=sample)
thread.start()
try:
    with TemporaryDirectory(prefix="triagemate-cvrf-first-insert-") as temp:
        root = Path(temp)
        path = root / "payload.json"
        products = [
            {"ProductID": f"p{j}", "Value": f"Synthetic profiling product {j}"}
            for j in range(20)
        ]
        with path.open("w") as f:
            f.write('{"ProductTree":')
            json.dump({"FullProductName": products}, f)
            f.write(',"Vulnerability":[')
            for i in range(n):
                if i:
                    f.write(",")
                value = {
                    "CVE": f"CVE-2099-{8000000 + i}",
                    "ProductStatuses": [
                        {"Type": 3, "ProductID": [p["ProductID"] for p in products]}
                    ],
                    "Remediations": [
                        {
                            "Type": 2,
                            "ProductID": [p["ProductID"] for p in products],
                            "Description": {"Value": str(9000000 + i * 2)},
                            "Supercedence": str(9000001 + i * 2),
                            "FixedBuild": "1.2.3.4",
                        }
                    ],
                }
                if note_bytes:
                    value["Notes"] = [
                        {
                            "Title": "Synthetic profiling note",
                            "Value": (
                                base64.b64encode(
                                    hashlib.shake_256(f"{i}/{offset}".encode()).digest(
                                        48000
                                    )
                                ).decode()[: min(64000, note_bytes - offset)]
                            ),
                        }
                        for offset in range(0, note_bytes, 64000)
                    ]
                json.dump(value, f)
                # Fixture generation must not retain the final large record
                # throughout product validation and database measurements.
                del value
            f.write("]}")
        path.chmod(0o600)
        size = path.stat().st_size
        with path.open("rb") as f:
            fingerprint = hashlib.file_digest(f, "sha256").hexdigest()
        if args.local_http:
            phase = "local_http_transfer"
            tick = time.monotonic()
            received = root / "received.json"
            local_http_copy(path, received)
            phases["local_http_transfer"] = time.monotonic() - tick
            with received.open("rb") as stream:
                assert hashlib.file_digest(stream, "sha256").hexdigest() == fingerprint
            path = received
        phase = "validation"
        tick = time.monotonic()
        payload = FilePayload(path.resolve(), fingerprint)
        now = datetime.now(timezone.utc)
        snapshot = PublicSnapshot(scope, run, now, now, "success", True, payload)
        phases["validation"] = time.monotonic() - tick
        phase = "registration"
        with local_database().connect() as conn:
            try:
                with conn.cursor() as c:
                    c.execute("SELECT pg_backend_pid()")
                    backend = c.fetchone()[0]
                    postmaster = process_parent(backend)
                    c.execute("SET LOCAL statement_timeout='120s'")
                    c.execute("SET LOCAL track_functions='all'")
                    authorize_connection(c, snapshot)
                    c.execute("SET LOCAL ROLE tm_pipeline_writer")
                phase = "persistence"
                tick = time.monotonic()
                persist_public(conn, snapshot)
                phases["persistence"] = time.monotonic() - tick
                with conn.cursor() as c:
                    phase = "integrity_checks"
                    tick = time.monotonic()
                    c.execute("SET CONSTRAINTS ALL IMMEDIATE")
                    phases["immediate_constraints"] = time.monotonic() - tick
                    c.execute(
                        "SELECT count(*) FROM evidence.observation_receipts WHERE collection_attempt_id=%s",
                        (run,),
                    )
                    counts["receipts"] = c.fetchone()[0]
                    assert counts["receipts"] == n
                    c.execute(
                        "SELECT count(*) FROM evidence_pipeline.cvrf_projection p JOIN evidence.observation_receipts r ON r.id=p.receipt_id WHERE r.collection_attempt_id=%s",
                        (run,),
                    )
                    counts["projections"] = c.fetchone()[0]
                    assert counts["projections"] == n * 100
                    c.execute(
                        "SELECT count(*) FROM evidence.source_revisions WHERE connection_id=%s",
                        (scope.connection_id,),
                    )
                    counts["new_revisions"] = c.fetchone()[0]
                    assert counts["new_revisions"] == n
                    c.execute("RESET ROLE")
                    c.execute(
                        "SELECT funcname,calls,total_time FROM pg_stat_xact_user_functions ORDER BY total_time DESC LIMIT 8"
                    )
                    functions = c.fetchall()
            finally:
                phase = "rollback"
                conn.rollback()
            with conn.cursor() as c:
                c.execute(
                    "SELECT count(*) FROM evidence.source_connections WHERE id=%s",
                    (scope.connection_id,),
                )
                assert c.fetchone() == (0,)
                c.execute(
                    "SELECT count(*) FROM evidence.collection_attempts WHERE id=%s",
                    (run,),
                )
                assert c.fetchone() == (0,)
            conn.rollback()
        backend = None
        postmaster = None
    assert not root.exists()
finally:
    stop.set()
    thread.join()
print(
    json.dumps(
        dict(
            records=n,
            products_per_record=20,
            note_bytes_per_record=note_bytes,
            note_pattern="mixed",
            input_bytes=size,
            seconds=round(time.monotonic() - start, 3),
            phases={k: round(v, 3) for k, v in phases.items()},
            memory=metrics,
            phase_memory=phase_metrics,
            samples=samples,
            verified_counts=counts,
            top_database_functions=functions,
            rollback_verified=True,
            temporary_directory_removed=True,
            local_http_transfer=args.local_http,
            measurement="100ms process samples; Python plus owning PostgreSQL backend and entire associated cluster PSS; cluster includes unrelated concurrent DB work and resident baseline; optional loopback HTTP only; no upstream TLS or UI rendering",
        )
    ),
    flush=True,
)
