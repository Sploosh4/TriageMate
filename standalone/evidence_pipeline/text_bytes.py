"""Exact UTF-8 measurements without allocating a complete second claim copy."""

import hashlib

_CHUNK_CHARACTERS = 262_144


def _chunks(value):
    if not isinstance(value, str):
        raise TypeError("UTF-8 claim measurement requires text")
    for start in range(0, len(value), _CHUNK_CHARACTERS):
        yield value[start : start + _CHUNK_CHARACTERS].encode("utf-8")


def utf8_size(value):
    return sum(len(chunk) for chunk in _chunks(value))


def utf8_sha256(value):
    digest = hashlib.sha256()
    for chunk in _chunks(value):
        digest.update(chunk)
    return digest.hexdigest()
