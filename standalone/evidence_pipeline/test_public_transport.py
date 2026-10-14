"""Synthetic transport responses; tests never contact upstream services."""

import gzip
import io

import pytest

from standalone.evidence_pipeline.collection import public_transport as transport


class Response(io.BytesIO):
    status = 200

    def __init__(self, data, headers=None):
        super().__init__(data)
        self.headers = headers or {}

    def getheader(self, name, default=None):
        return self.headers.get(name, default)


@pytest.fixture
def server(monkeypatch):
    class Connection:
        closed = False
        response = Response(b"synthetic")

        def __init__(self, host, timeout):
            self.host = host
            assert timeout == 30

        def request(self, method, path, headers):
            assert method == "GET"
            assert "Authorization" not in headers
            self.path = path

        def getresponse(self):
            return self.response

        def close(self):
            type(self).closed = True

    monkeypatch.setattr(transport.http.client, "HTTPSConnection", Connection)
    return Connection


def test_complete_response_and_fingerprints(server):
    result = transport.download("CISA")
    assert result.payload == result.wire == b"synthetic"
    assert len(result.wire_fingerprint) == 64
    assert result.started_at <= result.finished_at
    assert server.closed


def test_osv_native_advisory_route_and_reserved_character_encoding(server):
    with pytest.raises(ValueError, match="deferred"):
        transport.download("OSV", input_kind="advisories", advisory_id="RHSA-2099:1234")
    assert (
        transport.endpoint("OSV", input_kind="advisories", advisory_id="RHSA-2099:1234")
        == "https://api.osv.dev/v1/vulns/RHSA-2099%3A1234"
    )


@pytest.mark.parametrize(
    "identity", [None, "", "../x", "x/y", "x?y", "x#y", "x%2fy", "x" * 257, 123]
)
def test_osv_route_rejects_missing_and_unsafe_identities(identity):
    with pytest.raises(ValueError):
        transport.endpoint("OSV", input_kind="advisories", advisory_id=identity)


@pytest.mark.parametrize(
    "source,kind,cve,month",
    [
        ("CVE", "records", None, None),
        ("OSV", "records", None, None),
        ("OSV", "advisories", "CVE-2099-1234", None),
        ("OSV", "advisories", None, "2099-Sep"),
    ],
)
def test_advisory_request_cannot_change_source_or_mix_query_types(
    source, kind, cve, month
):
    with pytest.raises(ValueError):
        transport.endpoint(
            source, cve, input_kind=kind, month=month, advisory_id="x_synthetic"
        )


def test_msrc_month_download_uses_only_fixed_publisher_endpoint(server):
    result = transport.download("MSRC", month="2026-Sep")
    assert result.url == "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Sep"
    assert result.payload == b"synthetic"


@pytest.mark.parametrize(
    "source,kind,repository",
    [
        ("CVE", "records", "CVEProject/cvelistV5/main/cves"),
        ("CISA", "vulnrichment", "cisagov/vulnrichment/develop"),
    ],
)
@pytest.mark.parametrize("sequence,bucket", [("0123", "0xxx"), ("12345", "12xxx")])
def test_cve_repository_routes_preserve_identifiers(
    server, source, kind, repository, sequence, bucket
):
    cve = f"CVE-2099-{sequence}"
    result = transport.download(source, cve=cve, input_kind=kind)
    assert result.url == (
        f"https://raw.githubusercontent.com/{repository}/2099/{bucket}/{cve}.json"
    )
    assert result.payload == b"synthetic" and server.closed


@pytest.mark.parametrize(
    "cve", [None, "CVE-2099-123", "CVE-2099-1234/../x", "CVE-2099-1234?x=1", 1234]
)
def test_cve_repository_rejects_nonidentifiers(cve):
    with pytest.raises(ValueError):
        transport.endpoint("CVE", cve, input_kind="records")


@pytest.mark.parametrize(
    "source,kind,month",
    [
        ("CVE", None, None),
        ("CVE", "kev", None),
        ("CISA", "records", None),
        ("NVD", "vulnrichment", None),
        ("CVE", "records", "2026-Sep"),
        ("MSRC", "advisories", "2026-Sep"),
        ("MSRC", "security_updates", None),
    ],
)
def test_explicit_input_kind_cannot_select_another_source_route(source, kind, month):
    with pytest.raises(ValueError):
        transport.endpoint(source, "CVE-2099-1234", month=month, input_kind=kind)


def test_cve_repository_does_not_follow_redirects(server):
    server.response = Response(b"", {"Location": "https://example.invalid/record"})
    server.response.status = 302
    with pytest.raises(ValueError, match="HTTP"):
        transport.download("CVE", cve="CVE-2099-1234", input_kind="records")
    assert server.closed


@pytest.mark.parametrize(
    "source,cve,month",
    [
        ("NVD", None, "2026-Sep"),
        ("MSRC", "CVE-2026-1234", "2026-Sep"),
        ("MSRC", None, "2026-September"),
        ("MSRC", None, "2026-Sep/../Oct"),
        ("MSRC", None, 2026),
    ],
)
def test_month_request_rejects_wrong_source_or_ambiguous_route(source, cve, month):
    with pytest.raises(ValueError):
        transport.endpoint(source, cve, month=month)


def test_gzip_preserves_both_byte_sequences(server):
    server.response = Response(gzip.compress(b"synthetic CSV"))
    result = transport.download("FIRST")
    assert result.payload == b"synthetic CSV"
    assert result.wire != result.payload


@pytest.mark.parametrize(
    "source,cve",
    [("unknown", None), ("NVD", None), ("NVD", "../bad"), ("CISA", "CVE-2026-1234")],
)
def test_endpoint_rejects_unapproved_requests(source, cve):
    with pytest.raises(ValueError):
        transport.endpoint(source, cve)


def test_nvd_scopes_request_to_one_cve():
    assert transport.endpoint("NVD", "CVE-2026-1234").endswith("?cveId=CVE-2026-1234")


@pytest.mark.parametrize("status", [301, 302, 403, 429, 500, 206])
def test_http_failures_and_redirects_are_not_success(server, status):
    server.response.status = status
    with pytest.raises(ValueError, match="HTTP"):
        transport.download("CISA")
    assert server.closed


@pytest.mark.parametrize(
    "status,code",
    [
        (404, "public_not_found"),
        (410, "public_gone"),
        (401, "public_access_denied"),
        (403, "public_access_denied"),
        (429, "public_rate_limited"),
        (500, "public_unavailable"),
        (503, "public_unavailable"),
        (302, "public_http_failed"),
        (206, "public_http_failed"),
    ],
)
def test_http_outcomes_preserve_safe_reason_without_reading_body(server, status, code):
    server.response = Response(b"Synthetic response body must not be retained")
    server.response.status = status
    with pytest.raises(transport.PublicHTTPError) as caught:
        transport.download("NVD", cve="CVE-2099-1234")
    assert caught.value.code == code
    assert server.response.tell() == 0
    assert "Synthetic response" not in str(caught.value)
    assert server.closed


@pytest.mark.parametrize(
    "headers",
    [
        {"Content-Length": "100"},
        {"Content-Length": "-1"},
        {"Content-Length": "45000001"},
        {"Content-Encoding": "gzip"},
    ],
)
def test_invalid_transport_metadata(server, headers):
    server.response = Response(b"synthetic", headers)
    with pytest.raises(ValueError):
        transport.download("CISA")
    assert server.closed


@pytest.mark.parametrize("compressed", [False, True])
def test_download_above_frontend_result_budget(server, compressed):
    payload = b" " * 45_000_001 + b"synthetic public transport fixture"
    wire = gzip.compress(payload) if compressed else payload
    server.response = Response(wire, {"Content-Length": str(len(wire))})
    result = transport.download("FIRST" if compressed else "CISA")
    assert result.payload == payload
    assert server.closed


def test_corrupt_gzip_is_not_complete(server):
    server.response = Response(gzip.compress(b"synthetic")[:-3])
    with pytest.raises(ValueError, match="transport failed"):
        transport.download("FIRST")
    assert server.closed


def test_elapsed_budget(server, monkeypatch):
    times = iter([0, 61])
    monkeypatch.setattr(transport.time, "monotonic", lambda: next(times))
    with pytest.raises(ValueError, match="elapsed"):
        transport.download("CISA")
    assert server.closed


def test_first_only_follows_one_relative_dated_redirect(server, monkeypatch):
    redirect = Response(b"", {"Location": "epss_scores-2026-09-11.csv.gz"})
    redirect.status = 302
    responses = iter([redirect, Response(gzip.compress(b"synthetic"))])
    monkeypatch.setattr(server, "getresponse", lambda self: next(responses))
    result = transport.download("FIRST")
    assert result.url.endswith("/epss_scores-2026-09-11.csv.gz")
    assert result.payload == b"synthetic"


@pytest.mark.parametrize(
    "location",
    [
        "https://evil.invalid/x",
        "//evil.invalid/x",
        "/other",
        "epss_scores-2026-09-11.csv.gz?x=1",
    ],
)
def test_first_rejects_other_redirects(server, location):
    server.response = Response(b"", {"Location": location})
    server.response.status = 302
    with pytest.raises(ValueError, match="redirect"):
        transport.download("FIRST")


def test_msrc_endpoint_is_fixed_and_cve_scoped(server):
    assert (
        transport.endpoint("MSRC", "CVE-2099-1234")
        == "https://msrc.microsoft.com/csaf/advisories/2099/msrc_cve-2099-1234.json"
    )
    assert transport.download("MSRC", cve="CVE-2099-1234").payload == b"synthetic"
    for cve in (None, "../file", "CVE-2099-1234?x=1"):
        with pytest.raises(ValueError):
            transport.endpoint("MSRC", cve)


def test_cancel_between_reads_closes_transport(server):
    checks = iter([False, True])
    server.response = Response(b"s" * 131072)
    with pytest.raises(ValueError, match="cancelled"):
        transport._download_url(
            transport.endpoint("CISA"), cancelled=lambda: next(checks)
        )
    assert server.closed


def test_decoding_checks_the_same_deadline(server, monkeypatch):
    server.response = Response(gzip.compress(b"s" * 2_000_000))
    ticks = [0]
    original = transport.read_complete

    def read(*args, **kwargs):
        result = original(*args, **kwargs)
        ticks[0] = 61
        return result

    monkeypatch.setattr(transport.time, "monotonic", lambda: ticks[0])
    monkeypatch.setattr(transport, "read_complete", read)
    with pytest.raises(ValueError, match="elapsed"):
        transport.download("FIRST")
    assert server.closed


def test_slow_trickling_response_respects_elapsed_deadline():
    import http.client
    import threading
    import time
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "1000")
            self.end_headers()
            try:
                for _ in range(1000):
                    self.wfile.write(b"s")
                    self.wfile.flush()
                    time.sleep(0.01)
            except (BrokenPipeError, ConnectionResetError):
                pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=1)
    try:
        conn.request("GET", "/synthetic-trickle")
        response = conn.getresponse()
        start = time.monotonic()
        with pytest.raises((ValueError, TimeoutError)):
            transport.read_complete(response, deadline=start + 0.1, connection=conn)
        assert time.monotonic() - start < 1
    finally:
        conn.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_file_transport_keeps_exact_bytes_with_closed_handles(server, tmp_path):
    from .file_payload import FilePayload

    result = transport._download_url(
        "https://example.invalid/synthetic", save_to=tmp_path / "wire.bin"
    )
    assert isinstance(result.payload, FilePayload)
    assert result.wire_fingerprint == result.payload.fingerprint
    result.payload.verify()
    assert result.payload.path.read_bytes() == b"synthetic"
    assert result.payload.path.stat().st_mode & 0o077 == 0
    assert server.closed


def test_file_transport_does_not_return_incomplete_success(server, tmp_path):
    server.response = Response(b"synthetic", {"Content-Length": "100"})
    with pytest.raises(ValueError, match="incomplete"):
        transport._download_url(
            "https://example.invalid/synthetic", save_to=tmp_path / "wire.bin"
        )
    assert server.closed
    assert (tmp_path / "wire.bin").stat().st_mode & 0o077 == 0


def test_first_file_transport_retains_compressed_and_decoded_fingerprints(
    server, tmp_path
):
    import hashlib
    from .file_payload import FilePayload

    raw = b"synthetic public CSV\n" * 10000
    wire = gzip.compress(raw)
    server.response = Response(wire, {"Content-Length": str(len(wire))})
    result = transport.download("FIRST", save_to=tmp_path / "wire.bin")
    assert isinstance(result.wire, FilePayload) and isinstance(
        result.payload, FilePayload
    )
    assert result.wire_fingerprint == hashlib.sha256(wire).hexdigest()
    assert result.payload.fingerprint == hashlib.sha256(raw).hexdigest()
    assert result.payload.path.read_bytes() == raw
    assert server.closed


@pytest.mark.parametrize("failure", ["truncated", "cancelled", "timeout", "interrupt"])
def test_failed_gzip_file_decode_removes_only_owned_decoded_file(tmp_path, failure):
    import hashlib
    import time
    from .file_payload import FilePayload

    raw = gzip.compress(b"synthetic\n" * 10000)
    if failure == "truncated":
        raw = raw[:-5]
    wire = tmp_path / "wire.bin"
    wire.write_bytes(raw)
    wire.chmod(0o600)
    payload = FilePayload(wire.resolve(), hashlib.sha256(raw).hexdigest())

    def cancelled():
        if failure == "interrupt":
            raise KeyboardInterrupt("Synthetic interruption")
        return failure == "cancelled"

    destination = tmp_path / "decoded.bin"
    with pytest.raises((ValueError, EOFError, KeyboardInterrupt)):
        transport._decode_gzip_file(
            payload,
            destination,
            deadline=time.monotonic() + (-1 if failure == "timeout" else 30),
            cancelled=cancelled,
        )
    assert not destination.exists() and wire.read_bytes() == raw


def test_gzip_decode_does_not_replace_or_remove_existing_destination(tmp_path):
    import hashlib
    import time
    from .file_payload import FilePayload

    raw = gzip.compress(b"synthetic")
    wire = tmp_path / "wire.bin"
    wire.write_bytes(raw)
    wire.chmod(0o600)
    destination = tmp_path / "decoded.bin"
    destination.write_bytes(b"existing evidence")
    with pytest.raises(FileExistsError):
        transport._decode_gzip_file(
            FilePayload(wire.resolve(), hashlib.sha256(raw).hexdigest()),
            destination,
            deadline=time.monotonic() + 30,
            cancelled=lambda: False,
        )
    assert destination.read_bytes() == b"existing evidence"


@pytest.mark.parametrize("identity", ["2099-Jan", "2099-FEB", "2099-May-B"])
def test_msrc_native_publication_identifiers_keep_exact_route(identity):
    assert transport.endpoint(
        "MSRC", month=identity, input_kind="security_updates"
    ) == ("https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/" + identity)


@pytest.mark.parametrize(
    "identity",
    [
        "2099-May-B/../Jun",
        "2099-May?x=1",
        "2099-May#fragment",
        "2099-May%2f",
        "https://example.invalid",
        "2099-May-UNKNOWN",
    ],
)
def test_msrc_index_identifier_cannot_expand_url_authority(identity):
    with pytest.raises(ValueError):
        transport.endpoint("MSRC", month=identity, input_kind="security_updates")
