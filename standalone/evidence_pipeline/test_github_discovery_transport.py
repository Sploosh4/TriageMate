"""No real network: fixed GitHub API routes reuse the bounded public transport."""

from contextlib import nullcontext

import pytest

from standalone.evidence_pipeline.collection import public_transport as transport
from .test_public_transport import Response, server  # noqa: F401


@pytest.fixture(autouse=True)
def no_real_pacing(monkeypatch):
    from standalone.evidence_pipeline.collection import public_pacing

    monkeypatch.setattr(public_pacing, "paced", lambda source: nullcontext())


@pytest.mark.parametrize("kind", ["commits", "trees"])
def test_pinned_discovery_transport_and_headers(server, monkeypatch, kind):  # noqa: F811
    calls = []
    original = server.request

    def request(self, method, path, headers):
        calls.append((self.host, path, headers))
        original(self, method, path, headers)

    monkeypatch.setattr(server, "request", request)
    value = transport.download_github_object(kind, "a" * 40, source="CVE")
    assert value.wire == value.payload == b"synthetic"
    assert calls == [
        (
            "api.github.com",
            "/repos/CVEProject/cvelistV5/git/" + kind + "/" + "a" * 40,
            {
                "Accept-Encoding": "identity",
                "User-Agent": "TriageMate-evidence/1.0",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2026-03-10",
            },
        )
    ]
    assert server.closed


@pytest.mark.parametrize("status", [301, 302, 403, 404, 429, 500])
def test_discovery_http_failure_is_not_followed_or_retried(server, monkeypatch, status):  # noqa: F811
    server.response = Response(
        b"ignored", {"Location": "https://example.invalid/other"}
    )
    server.response.status = status
    calls = []
    original = server.request

    def request(self, *args, **kwargs):
        calls.append(1)
        original(self, *args, **kwargs)

    monkeypatch.setattr(server, "request", request)
    with pytest.raises(transport.PublicHTTPError) as caught:
        transport.download_github_object("trees", "a" * 40, source="CVE")
    assert len(calls) == 1 and server.closed
    if status == 429:
        assert caught.value.code == "public_rate_limited"


@pytest.mark.parametrize(
    "headers,payload",
    [
        ({"Content-Length": "8"}, b"short"),
        ({"Content-Length": "999999999"}, b"small"),
        ({"Content-Encoding": "gzip"}, b"encoded"),
        ({}, b""),
    ],
)
def test_discovery_rejects_incomplete_or_invalid_response(server, headers, payload):  # noqa: F811
    server.response = Response(payload, headers)
    with pytest.raises(ValueError):
        transport.download_github_object("trees", "a" * 40, source="CVE")
    assert server.closed


@pytest.mark.parametrize(
    "kind,identity",
    [
        ("trees", "main"),
        ("trees", "a" * 40 + "?recursive=1"),
        ("blobs", "a" * 40),
        ("../trees", "a" * 40),
    ],
)
def test_discovery_bad_route_does_not_open_connection(monkeypatch, kind, identity):
    monkeypatch.setattr(
        transport.http.client,
        "HTTPSConnection",
        lambda *a, **k: pytest.fail("Invalid route opened a connection"),
    )
    with pytest.raises(ValueError):
        transport.download_github_object(kind, identity, source="CVE")
