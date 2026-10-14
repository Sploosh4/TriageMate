"""Incremental object members with the same exact-number/field validation as JSON.

The reader owns its input handle. Root key uniqueness uses a private temporary
SQLite index, so a growing feed does not require a growing in-memory key set.
Only one root member is materialized at a time; its own structure still matters.
"""

from decimal import Decimal
import sqlite3

from .temporary_index import temporary_index
import json
import re

import ijson

from standalone.evidence_pipeline.parsing.public_inputs import (
    MAX_DEPTH,
    MAX_PUBLIC_RECORDS,
    MAX_TEXT,
    _text,
)

# Validate original string tokens before the C parser can normalize malformed
# surrogates. The Python backend retains long consumed prefixes for some chunk
# alignments, so it does not provide the memory behavior needed here.
_PARSER = ijson.get_backend("yajl2_c")
_MARKERS = re.compile(rb'["\\]')


class StringGuard:
    def __init__(self, stream):
        self.stream = stream
        self.token = None
        self.escaped = False

    def _append(self, chunk):
        self.token.extend(chunk)
        # Every accepted Unicode character fits in at most two six-byte JSON
        # escapes. This bounds lexer buffering without rejecting valid strings.
        if len(self.token) > MAX_TEXT * 12 + 2:
            raise ValueError("Expected bounded text")

    def read(self, size):
        data = self.stream.read(size)
        start = 0
        for marker in _MARKERS.finditer(data):
            position = marker.start()
            if self.token is None:
                if marker[0] == b'"':
                    self.token = bytearray(b'"')
                    self.escaped = False
            else:
                self._append(data[start : position + 1])
                if position > start:
                    self.escaped = False
                if self.escaped:
                    self.escaped = False
                elif marker[0] == b"\\":
                    self.escaped = True
                else:
                    try:
                        # Plain ASCII has no escapes or surrogate encoding to
                        # normalize. The streaming parser still checks JSON
                        # syntax and _validated_events checks decoded text.
                        if self.token.isascii() and b"\\" not in self.token:
                            if len(self.token) - 2 > MAX_TEXT:
                                raise ValueError("Expected bounded text")
                        else:
                            _text(json.loads(self.token), empty=True)
                    except (UnicodeError, json.JSONDecodeError) as exc:
                        raise ValueError("Invalid public JSON string") from exc
                    self.token = None
            start = position + 1
        if self.token is not None:
            self._append(data[start:])
            if len(data) > start:
                self.escaped = False
            if not data and size:
                raise ValueError("Incomplete public JSON string")
        return data


class WithoutBOM:
    def __init__(self, stream):
        self.stream = stream
        self.prefix = b""
        while len(self.prefix) < 3:
            chunk = stream.read(3 - len(self.prefix))
            if not chunk:
                break
            self.prefix += chunk
        if self.prefix == b"\xef\xbb\xbf":
            self.prefix = b""

    def read(self, size):
        if size < 0:
            raise ValueError("Streaming JSON requires bounded reads")
        prefix, self.prefix = self.prefix[:size], self.prefix[size:]
        return prefix + self.stream.read(size - len(prefix))


class UniqueObject(dict):
    def __setitem__(self, key, value):
        if key in self:
            raise ValueError("Duplicate JSON member")
        super().__setitem__(key, value)


class DiscardedValue:
    """Validate discarded nested object keys without retaining their values."""

    value = None

    def __init__(self, seen):
        self.seen = seen
        self.stack = []
        self.next_id = 0

    def event(self, event, value):
        if event == "start_map":
            self.next_id += 1
            self.stack.append(self.next_id)
        elif event == "start_array":
            self.stack.append(None)
        elif event == "map_key":
            try:
                self.seen.execute(
                    "INSERT INTO discarded_keys VALUES (?,?)", (self.stack[-1], value)
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("Duplicate JSON member") from exc
        elif event in ("end_map", "end_array"):
            identity = self.stack.pop()
            if identity is not None:
                self.seen.execute(
                    "DELETE FROM discarded_keys WHERE container=?", (identity,)
                )


def document_array(
    stream, name, *, cancelled=lambda: False, materialize_items=True, required=True
):
    """Yield root members and individual members of one designated root array.

    Results are (kind, root_key, value), with kind member, array or item. The
    array marker is emitted once, including for an empty array. With
    materialize_items=False, items yield None after structural validation with
    nested key uniqueness checked on disk. Root metadata is still materialized.
    This supports metadata-only passes, not acceptance of source records. Selection uses
    structural depth rather than dotted parser paths, so literal dotted keys
    cannot masquerade as array entries. Consume through EOF before acceptance.
    The array is required by default. Callers opting out must validate the
    source-specific envelope before treating its absence as a complete input.
    """
    with temporary_index() as seen:
        seen.execute("CREATE TABLE root_keys (name TEXT PRIMARY KEY)")
        seen.execute(
            "CREATE TABLE discarded_keys (container INTEGER, name TEXT, "
            "PRIMARY KEY(container,name)) WITHOUT ROWID"
        )
        depth, key, in_array, found, builder = 0, None, False, False, None
        try:
            for _, event, value in _validated_events(stream, cancelled, seen):
                if depth == 0:
                    depth = 1
                    continue
                if depth == 1 and event == "end_map":
                    depth = 0
                    continue
                if depth == 1 and event == "map_key":
                    key = value
                    continue
                if depth == 1 and key == name and builder is None:
                    if event != "start_array":
                        raise ValueError("Expected designated JSON array")
                    in_array, found, depth = True, True, 2
                    yield "array", name, None
                    continue
                if in_array and depth == 2 and event == "end_array":
                    in_array, depth, key = False, 1, None
                    continue
                if builder is None:
                    builder = (
                        DiscardedValue(seen)
                        if in_array and not materialize_items
                        else ijson.common.ObjectBuilder(map_type=UniqueObject)
                    )
                builder.event(event, value)
                if event in ("start_map", "start_array"):
                    depth += 1
                elif event in ("end_map", "end_array"):
                    depth -= 1
                if depth == (2 if in_array else 1):
                    yield "item" if in_array else "member", key, builder.value
                    builder = None
                    if not in_array:
                        key = None
            if required and not found:
                raise ValueError("Missing designated JSON array")
        except (ijson.JSONError, UnicodeError, OverflowError) as exc:
            raise ValueError("Invalid public JSON") from exc


def object_members(stream, *, cancelled=lambda: False):
    """Yield all members of exactly one JSON object; errors can occur at EOF.

    Callers must exhaust this iterator before publishing a successful snapshot.
    No byte ceiling is applied. Decimal values retain their source precision.
    """
    with temporary_index() as seen:
        seen.execute("CREATE TABLE root_keys (name TEXT PRIMARY KEY)")

        try:
            yield from ijson.kvitems(
                _validated_events(stream, cancelled, seen),
                "",
                map_type=UniqueObject,
            )
        except (ijson.JSONError, UnicodeError, OverflowError) as exc:
            raise ValueError("Invalid public JSON") from exc


def _validated_events(stream, cancelled, seen):
    stack = []
    root_seen = False
    for prefix, event, value in _PARSER.parse(
        StringGuard(WithoutBOM(stream)), use_float=False
    ):
        if cancelled():
            raise ValueError("JSON processing cancelled")
        if not root_seen:
            if event != "start_map":
                raise ValueError("Expected JSON object")
            root_seen = True
        if event in ("end_map", "end_array"):
            stack.pop()
        elif event == "map_key":
            _text(value, empty=True)
            if len(stack) == 1:
                try:
                    seen.execute("INSERT INTO root_keys VALUES (?)", (value,))
                except sqlite3.IntegrityError as exc:
                    raise ValueError("Duplicate JSON member") from exc
        else:
            if len(stack) > MAX_DEPTH:
                raise ValueError("JSON nesting limit exceeded")
            if stack and stack[-1][0] == "array":
                stack[-1][1] += 1
                if stack[-1][1] > MAX_PUBLIC_RECORDS:
                    raise ValueError("Expected bounded JSON array")
            if event == "start_map":
                stack.append(["map", 0])
            elif event == "start_array":
                stack.append(["array", 0])
            elif event == "string":
                _text(value, empty=True)
            elif isinstance(value, Decimal) and not value.is_finite():
                raise ValueError("Nonfinite JSON number")
        yield prefix, event, value
    if not root_seen or stack:
        raise ValueError("Incomplete JSON object")
    if cancelled():
        raise ValueError("JSON processing cancelled")
