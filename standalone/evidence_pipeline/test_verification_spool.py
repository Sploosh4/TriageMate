"""Spooling preserves exact verifier values, replayable reads and cleanup."""

from decimal import Decimal
import sqlite3
import random
import tracemalloc

import pytest

from .verification_spool import VerificationSpool


def test_rows_are_repeatable_and_preserve_types():
    values = [{"value": Decimal("0.000000000000000000123"), "flag": False}, {"zero": 0}]
    with VerificationSpool() as spool:
        rows = spool.rows(iter(values))
        assert len(rows) == 2 and rows == values and list(rows) == values
        assert rows[-1] == values[-1] and rows[:] == values
        assert rows[0]["value"] == Decimal("0.000000000000000000123")
        with pytest.raises(IndexError):
            rows[2]
        assert spool.rows([]) == []
        rows[0]["flag"] = True
        assert rows[0]["flag"] is False


def test_mapping_preserves_dictionary_semantics_and_nested_reads():
    with VerificationSpool() as spool:
        mapping = spool.mapping([("a", 1), ("b", {"v": Decimal("1.23")}), ("a", 2)])
        assert len(mapping) == 2 and mapping["a"] == 2
        assert mapping.get("missing") is None and "missing" not in mapping
        assert dict(mapping.items()) == {"a": 2, "b": {"v": Decimal("1.23")}}
        assert list(mapping.values()) == [mapping[key] for key in mapping]
        for key in mapping:
            assert key in mapping
            assert mapping[key] is not None
        with pytest.raises(KeyError):
            mapping["missing"]


@pytest.mark.parametrize("failure", [False, True])
def test_private_spool_cleanup_on_success_and_failure(failure):
    connection = None
    try:
        with VerificationSpool() as spool:
            connection = spool.connection
            spool.rows([{"synthetic": "private temporary data"}])
            if failure:
                raise RuntimeError("synthetic interrupted verification")
    except RuntimeError:
        assert failure
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        connection.execute("SELECT 1")


def test_increasing_row_payload_does_not_accumulate_in_python_memory():
    peaks = []
    for count in (100, 10000):
        tracemalloc.start()
        with VerificationSpool() as spool:
            rows = spool.rows({"row": n, "payload": "x" * 8192} for n in range(count))
            assert len(rows) == count and rows[-1]["row"] == count - 1
            peaks.append(tracemalloc.get_traced_memory()[1])
        tracemalloc.stop()
    assert max(peaks) < 2 * 1024 * 1024


@pytest.mark.parametrize("signal_name", ["SIGTERM", "SIGKILL"])
def test_linux_termination_leaves_no_spool_files(tmp_path, signal_name):
    import json
    import os
    from pathlib import Path
    import signal
    import subprocess
    import sys

    if sys.platform != "linux":
        pytest.skip("Checks the supported Linux host's anonymous SQLite files")
    code = """
import os, json, time
from standalone.evidence_pipeline.verification_spool import VerificationSpool
with VerificationSpool() as spool:
    spool.connection.execute('PRAGMA cache_size=-128')
    spool.rows({'synthetic': 'x' * 8192, 'row': n} for n in range(2000))
    files=[]
    for entry in os.scandir('/proc/self/fd'):
        try:
            name=os.readlink(entry.path)
            if 'etilqs' in name:
                files.append((name,os.stat(entry.path).st_mode & 0o777))
        except FileNotFoundError:
            pass
    print(json.dumps(files),flush=True)
    time.sleep(30)
"""
    child = subprocess.Popen(
        [sys.executable, "-c", code],
        stdout=subprocess.PIPE,
        text=True,
        env={**os.environ, "SQLITE_TMPDIR": str(tmp_path)},
    )
    try:
        files = json.loads(child.stdout.readline())
        assert files and all(
            name.endswith(" (deleted)") and mode == 0o600 for name, mode in files
        )
        child.send_signal(getattr(signal, signal_name))
        child.wait(timeout=10)
        assert not list(Path(tmp_path).iterdir())
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=10)
        child.stdout.close()


def test_large_values_are_verified_without_entering_lookup_cache():
    with VerificationSpool() as spool:
        mapping = spool.mapping((str(n), {"value": "x" * 70000}) for n in range(70))
        for n in range(70):
            assert len(mapping[str(n)]["value"]) == 70000
        assert not mapping._cache
        small = spool.mapping((str(n), {"value": n}) for n in range(70))
        for n in range(70):
            assert small[str(n)] == {"value": n}
        assert len(small._cache) == 64
        small["69"]["value"] = "changed"
        assert small["69"] == {"value": 69}


def test_spool_disk_exhaustion_fails_verification_and_closes_storage():
    connection = None
    with pytest.raises(sqlite3.OperationalError, match="full"):
        with VerificationSpool() as spool:
            connection = spool.connection
            # Test-only scratch quota; no evidence/import/storage cap is installed.
            connection.execute("PRAGMA max_page_count=3")
            spool.rows([{"synthetic": random.Random(7).randbytes(32768)}])
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        connection.execute("SELECT 1")


def test_reference_iteration_streams_payloads_without_a_temporary_sort():
    with VerificationSpool() as spool:
        expected = [
            {"id": key, "payload": "synthetic" * 10_000} for key in ("z", "b", "a", "y")
        ]
        source = spool.rows(expected)
        indexed = spool.reference_mapping(source, "id")
        nested = spool.reference_mapping(indexed, "id", lambda row: row["id"] != "b")
        for mapping, rows in (
            (indexed, expected),
            (nested, [expected[0], *expected[2:]]),
        ):
            queries = []
            spool.connection.set_trace_callback(queries.append)
            try:
                assert list(mapping.values()) == rows
                assert list(mapping.items()) == [(row["id"], row) for row in rows]
            finally:
                spool.connection.set_trace_callback(None)
            assert queries
            for query in queries:
                plan = spool.connection.execute(
                    "EXPLAIN QUERY PLAN " + query
                ).fetchall()
                assert not any("TEMP B-TREE" in step[-1] for step in plan), plan


def test_reference_indexes_preserve_values_without_copying_large_rows():
    with VerificationSpool() as spool:
        rows = spool.rows(
            {
                "id": str(n),
                "amount": Decimal("1.234567890123456789"),
                "payload": "x" * 200_000,
                "selected": n % 2 == 0,
            }
            for n in range(20)
        )
        before = spool.connection.execute("PRAGMA page_count").fetchone()[0]
        indexed = spool.reference_mapping(rows, "id")
        selected = spool.reference_mapping(indexed, "id", lambda row: row["selected"])
        after = spool.connection.execute("PRAGMA page_count").fetchone()[0]
        page_size = spool.connection.execute("PRAGMA page_size").fetchone()[0]
        assert (after - before) * page_size < 100_000
        assert len(indexed) == 20 and len(selected) == 10
        assert set(selected) == {str(n) for n in range(0, 20, 2)}
        assert dict(selected.items()) == {
            row["id"]: row for row in rows if row["selected"]
        }
        assert list(selected.values()) == [selected[key] for key in selected]
        assert selected["0"] == rows[0]
        selected["0"]["amount"] = 0
        assert selected["0"]["amount"] == Decimal("1.234567890123456789")
        assert "1" not in selected and selected.get("1") is None
        with pytest.raises(KeyError):
            selected["missing"]


def test_reference_index_rejects_foreign_spool_and_duplicate_identity():
    with VerificationSpool() as spool, VerificationSpool() as other:
        with pytest.raises(ValueError, match="this spool"):
            spool.reference_mapping(other.rows([{"id": "a"}]), "id")
        with pytest.raises(sqlite3.IntegrityError):
            spool.reference_mapping(spool.rows([{"id": "a"}, {"id": "a"}]), "id")


def test_reference_row_identity_is_not_the_external_mapping_key():
    with VerificationSpool() as spool:
        source = spool.mapping(
            [
                ("900", {"id": "b", "value": 1}),
                ("arbitrary", {"id": "a", "value": 2}),
                ("900", {"id": "b", "value": 3}),
            ]
        )
        indexed = spool.reference_mapping(source, "id")
        nested = spool.reference_mapping(indexed, "id", lambda row: row["value"] > 2)
        assert dict(indexed.items()) == {
            "b": {"id": "b", "value": 3},
            "a": {"id": "a", "value": 2},
        }
        assert dict(nested.items()) == {"b": {"id": "b", "value": 3}}
        assert "900" not in indexed and "arbitrary" not in indexed
        with pytest.raises(KeyError):
            nested["a"]


def test_grouped_identities_are_exact_repeatable_sets():
    with VerificationSpool() as spool:
        grouped = spool.grouped_identities(
            iter([("a", "1"), ("b", "3"), ("a", "2"), ("a", "1")])
        )
        assert len(grouped) == 2 and set(grouped) == {"a", "b"}
        assert dict(grouped.items()) == {"a": {"1", "2"}, "b": {"3"}}
        grouped["a"].clear()
        assert grouped["a"] == {"1", "2"} and grouped.get("missing", set()) == set()
        with pytest.raises(KeyError):
            grouped["missing"]


def test_grouped_identity_volume_does_not_accumulate_in_python_memory():
    for count in (100, 100_000):
        tracemalloc.start()
        try:
            with VerificationSpool() as spool:
                groups = spool.grouped_identities(
                    (str(n), str(n)) for n in range(count)
                )
                assert len(groups) == count and groups[str(count - 1)] == {
                    str(count - 1)
                }
                assert tracemalloc.get_traced_memory()[1] < 1024 * 1024
        finally:
            tracemalloc.stop()


@pytest.mark.parametrize("compressible", [True, False])
def test_scratch_encoding_preserves_large_values_and_limits_decoded_cache(compressible):
    payload = (
        b"synthetic-row-" * 100_000
        if compressible
        else random.Random(13).randbytes(1_300_000)
    )
    expected = {
        "id": "row",
        "payload": payload,
        "amount": Decimal("0.1234567890123456789"),
    }
    with VerificationSpool() as spool:
        rows = spool.rows([expected])
        stored = spool.connection.execute(
            f"SELECT length(value) FROM {rows.table}"
        ).fetchone()[0]
        assert stored < len(payload) // 20 if compressible else stored >= len(payload)
        indexed = spool.reference_mapping(rows, "id")
        nested = spool.reference_mapping(indexed, "id")
        for value in (
            rows[0],
            list(rows)[0],
            indexed["row"],
            nested["row"],
            list(nested.values())[0],
        ):
            assert value == expected
        assert not indexed._cache and not nested._cache


def test_corrupt_compressed_scratch_is_not_accepted():
    import zlib

    with VerificationSpool() as spool:
        rows = spool.rows([{"payload": "synthetic" * 10000}])
        spool.connection.execute(
            f"UPDATE {rows.table} SET value=substr(value,1,length(value)-1)"
        )
        with pytest.raises((ValueError, zlib.error)):
            rows[0]
