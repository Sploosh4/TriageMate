"""Claim spooling preserves exact text and closes resources on interrupted checks."""

from contextlib import contextmanager
from types import SimpleNamespace
import tempfile

import pytest

from standalone.evidence_pipeline.persistence.claim_lookup import (
    ClaimLookup,
    public_claims,
)


def test_exact_random_access_preserves_unicode_newlines_empty_and_large_claims():
    expected = {"empty": "", "unicode": 'α🙂\r\n"claim"\\', "large": "🙂x" * 100_000}
    with tempfile.TemporaryFile(mode="w+t", encoding="utf-8", newline="") as stream:
        claims = ClaimLookup(stream)
        for key, value in expected.items():
            claims.add(key, value)
        stream.flush()
        assert len(claims) == 3
        assert set(claims) == set(expected)
        for key in ["large", "empty", "unicode", "large"]:
            assert claims[key] == expected[key]
        with pytest.raises(KeyError):
            claims["missing"]
        with pytest.raises(AssertionError, match="Duplicate"):
            claims.add("unicode", "replacement")
        assert claims["unicode"] == expected["unicode"]
        offset, _ = claims.offsets["large"]
        stream.seek(offset)
        stream.truncate()
        with pytest.raises(AssertionError, match="truncated"):
            claims["large"]


@pytest.mark.parametrize("failure", [None, ValueError, KeyboardInterrupt])
def test_named_cursor_and_anonymous_spool_close_on_exit(failure):
    class Source:
        itersize = None
        closed = False

        def execute(self, query, parameters):
            assert "source_revision_id::text,claim" in query
            assert parameters == (65_536,)
            self.large = " > " in query

        def __iter__(self):
            assert self.itersize == (1 if self.large else 256)
            if not self.large:
                yield "synthetic-revision", "synthetic claim"

    source = Source()

    @contextmanager
    def cursor(*, name):
        assert name.startswith("verify_claims_")
        try:
            yield source
        finally:
            source.closed = True

    outer = SimpleNamespace(connection=SimpleNamespace(cursor=cursor))
    stream = None
    try:
        with public_claims(outer) as claims:
            stream = claims.stream
            assert source.closed
            assert claims["synthetic-revision"] == "synthetic claim"
            if failure:
                raise failure()
    except (ValueError, KeyboardInterrupt):
        assert failure is not None
    assert source.closed and stream.closed


def test_appending_after_a_lookup_does_not_overwrite_prior_claims():
    with tempfile.TemporaryFile(mode="w+t", encoding="utf-8", newline="") as stream:
        claims = ClaimLookup(stream)
        claims.add("first", "first synthetic claim")
        claims.add("second", "second synthetic claim")
        assert claims["first"] == "first synthetic claim"
        claims.add("third", "third synthetic claim")
        assert claims["second"] == "second synthetic claim"
        assert claims["third"] == "third synthetic claim"


def test_interrupted_acquisition_does_not_yield_partial_claim_inventory(monkeypatch):
    from standalone.evidence_pipeline.persistence import claim_lookup

    streams = []
    original = tempfile.TemporaryFile

    def temporary(*args, **kwargs):
        stream = original(*args, **kwargs)
        streams.append(stream)
        return stream

    monkeypatch.setattr(claim_lookup.tempfile, "TemporaryFile", temporary)

    class Source:
        closed = False

        def execute(self, query, parameters):
            pass

        def __iter__(self):
            yield "first", "synthetic first claim"
            raise OSError("synthetic interrupted source")

    source = Source()

    @contextmanager
    def cursor(*, name):
        try:
            yield source
        finally:
            source.closed = True

    outer = SimpleNamespace(connection=SimpleNamespace(cursor=cursor))
    with pytest.raises(OSError, match="interrupted"):
        with public_claims(outer):
            pytest.fail("Partial claim inventory was exposed")
    assert source.closed and len(streams) == 1 and streams[0].closed
