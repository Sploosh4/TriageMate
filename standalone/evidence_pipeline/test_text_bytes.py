"""Chunking preserves exact claims, including Unicode and encoding rejection."""

import hashlib
import tracemalloc

import pytest

from .text_bytes import utf8_size, utf8_sha256


@pytest.mark.parametrize(
    "text", ["", "plain", "é漢😀", "a" * 262_143 + "😀é" + "漢" * 300_000]
)
def test_exact_utf8_identity_and_size(text):
    encoded = text.encode("utf-8")
    assert utf8_size(text) == len(encoded)
    assert utf8_sha256(text) == hashlib.sha256(encoded).hexdigest()


@pytest.mark.parametrize("function", [utf8_size, utf8_sha256])
def test_invalid_surrogate_is_not_replaced(function):
    with pytest.raises(UnicodeEncodeError):
        function("a" * 262_144 + "\ud800")


@pytest.mark.parametrize("function", [utf8_size, utf8_sha256])
def test_large_claim_encoding_has_bounded_temporary_allocation(function):
    text = "😀" * 3_000_000
    tracemalloc.start()
    try:
        function(text)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    # Includes the previous yielded chunk, the new slice and its UTF-8 bytes.
    assert peak < 4_000_000
