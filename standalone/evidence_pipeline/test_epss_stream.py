"""File-backed EPSS preserves parser semantics, identities and cleanup."""

import hashlib
import pytest

from standalone.evidence_pipeline.parsing.epss_stream import parse_epss_file
from .file_payload import FilePayload
from standalone.evidence_pipeline.parsing.public_inputs import parse_epss_csv
from standalone.evidence_pipeline.parsing.public_records import normalize_public
from .test_public_inputs import scope, epss


def saved(tmp_path, payload):
    path = tmp_path / "epss.csv"
    path.write_bytes(payload)
    path.chmod(0o600)
    return FilePayload(path.resolve(), hashlib.sha256(payload).hexdigest())


def test_streamed_records_and_claims_match_bytes(tmp_path):
    raw = epss()
    payload = saved(tmp_path, raw)
    ordinary = parse_epss_csv(raw, scope=scope("FIRST"))
    streamed = parse_epss_file(payload, scope=scope("FIRST"))
    assert list(streamed.records) == list(ordinary.records)
    assert list(
        normalize_public(parse_epss_file(payload, scope=scope("FIRST")))
    ) == list(normalize_public(ordinary))
    assert streamed.input_fingerprint == ordinary.input_fingerprint


@pytest.mark.parametrize(
    "tail",
    [
        b"CVE-2026-9999999,0.1,0.2\n",
        b"CVE-2026-12345,NaN,0.2\n",
        b"bad,0.1,0.2\n",
        b"CVE-2026-12345,1.1,0.2\n",
        b"\xff\n",
        b'"unfinished',
    ],
)
def test_late_invalid_rows_cannot_be_accepted(tmp_path, tail):
    raw = epss() + tail
    with pytest.raises(ValueError):
        list(parse_epss_file(saved(tmp_path, raw), scope=scope("FIRST")).records)


def test_normalizer_close_removes_temporary_duplicate_index(tmp_path, monkeypatch):
    import standalone.evidence_pipeline.parsing.epss_stream as module

    from contextlib import contextmanager
    import sqlite3

    connections = []
    original = module.temporary_index

    @contextmanager
    def temporary():
        with original() as connection:
            connections.append(connection)
            yield connection

    monkeypatch.setattr(module, "temporary_index", temporary)
    feed = parse_epss_file(saved(tmp_path, epss()), scope=scope("FIRST"))
    records = normalize_public(feed)
    next(records)
    assert connections and connections[0].execute(
        "SELECT count(*) FROM cves"
    ).fetchone() == (1,)
    records.close()
    for connection in connections:
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            connection.execute("SELECT 1")
