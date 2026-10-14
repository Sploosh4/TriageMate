"""Streamed source claims retain strict JSON semantics across chunk boundaries."""

import io
import json
from decimal import Decimal
import pytest
from .json_stream import object_members
from standalone.evidence_pipeline.parsing.public_inputs import _json


class SmallReads(io.BytesIO):
    def read(self, size=-1):
        assert size >= 0, "No full-file read allowed"
        return super().read(min(size, 7))

    def readinto(self, target):
        value = self.read(len(target))
        target[: len(value)] = value
        return len(value)


def test_exact_values_and_multibyte_text_across_small_reads():
    raw = b'{"synthetic.one":{"decimal":0.123456789012345678901,"zero":0,"flag":false,"text":"\\u00e9"},"empty":{}}'
    result = dict(object_members(SmallReads(raw)))
    assert result == _json(raw.decode())
    assert result["synthetic.one"]["decimal"] == Decimal("0.123456789012345678901")
    assert dict(object_members(SmallReads('{"日本語":"🦜"}'.encode()))) == {
        "日本語": "🦜"
    }


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"[]",
        b"null",
        b"{} {}",
        b'{"x":1,}',
        b'{"x":NaN}',
        b'{"x":Infinity}',
        b'{"x":01}',
        b'{"x":1',
        b'{"x":"bad\x00"}',
        b'{"x":1,"x":2}',
        b'{"x":{"y":1,"y":2}}',
        b'{"x":"\\ud800"}',
        b'{"x":"\xff"}',
        b'{"x":[1,]}',
        b'{"x":true garbage}',
    ],
)
def test_invalid_input_is_rejected_even_after_prior_members(raw):
    with pytest.raises(ValueError):
        list(object_members(SmallReads(raw)))


def test_depth_and_text_limits_remain_active():
    from standalone.evidence_pipeline.parsing.public_inputs import MAX_DEPTH, MAX_TEXT

    for raw in [
        b'{"x":' + b"[" * (MAX_DEPTH + 1) + b"0" + b"]" * (MAX_DEPTH + 1) + b"}",
        json.dumps({"x": "a" * (MAX_TEXT + 1)}).encode(),
    ]:
        with pytest.raises(ValueError):
            list(object_members(io.BytesIO(raw)))


def test_late_duplicate_and_truncation_cannot_be_successful_prefix():
    iterator = object_members(SmallReads(b'{"one":1,"two":2,"one":3}'))
    assert next(iterator) == ("one", 1)
    with pytest.raises(ValueError):
        list(iterator)


def test_cancellation_rejects_even_empty_object():
    with pytest.raises(ValueError, match="cancelled"):
        list(object_members(io.BytesIO(b"{}"), cancelled=lambda: True))


def test_bom_is_supported_without_closing_the_callers_stream():
    stream = SmallReads(b'\xef\xbb\xbf{"synthetic":false}')
    assert list(object_members(stream)) == [("synthetic", False)]
    assert not stream.closed


def test_temporary_key_index_is_removed_on_failure_and_generator_close(
    monkeypatch, tmp_path
):
    import sqlite3
    from contextlib import contextmanager
    import standalone.evidence_pipeline.json_stream as module

    connections = []
    original = module.temporary_index

    @contextmanager
    def temporary():
        with original() as connection:
            connections.append(connection)
            yield connection

    monkeypatch.setattr(module, "temporary_index", temporary)
    with pytest.raises(ValueError):
        list(object_members(SmallReads(b'{"a":1,"a":2}')))
    iterator = object_members(SmallReads(b'{"one":1,"two":2}'))
    assert next(iterator) == ("one", 1)
    iterator.close()
    assert len(connections) == 2
    for connection in connections:
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            connection.execute("SELECT 1")


def test_original_string_validation_handles_escapes_at_every_small_boundary():
    import itertools

    for pieces in itertools.product(["\\", '"', "\n", "é", "🦜", "plain"], repeat=3):
        value = "".join(pieces)
        raw = json.dumps({"synthetic": value}).encode()
        assert dict(object_members(SmallReads(raw))) == {"synthetic": value}


def test_escaped_unicode_maximum_is_valid_but_oversized_lexer_token_stops_early():
    from standalone.evidence_pipeline.parsing.public_inputs import MAX_TEXT

    value = "🦜" * MAX_TEXT
    raw = json.dumps({"synthetic": value}).encode()
    assert dict(object_members(io.BytesIO(raw))) == {"synthetic": value}
    stream = io.BytesIO(b'{"synthetic":"' + b"a" * (MAX_TEXT * 20) + b'"}')
    with pytest.raises(ValueError, match="bounded text"):
        list(object_members(stream))
    assert stream.tell() < len(stream.getvalue())


def test_document_array_streams_members_with_structural_identity():
    from .json_stream import document_array

    payload = b'{"Vulnerability.item":{"literal":true},"Vulnerability":[{"a":1},false,[0,2]],"tail":null}'
    assert list(document_array(io.BytesIO(payload), "Vulnerability")) == [
        ("member", "Vulnerability.item", {"literal": True}),
        ("array", "Vulnerability", None),
        ("item", "Vulnerability", {"a": 1}),
        ("item", "Vulnerability", False),
        ("item", "Vulnerability", [0, 2]),
        ("member", "tail", None),
    ]
    assert list(
        document_array(io.BytesIO(b'{"Vulnerability":[]}'), "Vulnerability")
    ) == [("array", "Vulnerability", None)]


@pytest.mark.parametrize(
    "payload",
    [
        b"{}",
        b'{"Vulnerability":{}}',
        b'{"Vulnerability":[],"Vulnerability":[]}',
        b'{"Vulnerability":[{"a":1,"a":2}]}',
        b'{"Vulnerability":[],"tail":{"x":1,"x":2}}',
        b'{"Vulnerability":[{}],"tail":',
    ],
)
@pytest.mark.parametrize("materialize", [True, False])
def test_document_array_validates_the_entire_document(payload, materialize):
    from .json_stream import document_array

    with pytest.raises(ValueError):
        list(
            document_array(
                io.BytesIO(payload), "Vulnerability", materialize_items=materialize
            )
        )


def test_metadata_pass_discards_values_but_retains_later_metadata():
    from .json_stream import document_array

    payload = b'{"Vulnerability":[{"same":1,"nested":{"same":2}},false,[0,2]],"tail":{"zero":0}}'
    assert list(
        document_array(SmallReads(payload), "Vulnerability", materialize_items=False)
    ) == [
        ("array", "Vulnerability", None),
        ("item", "Vulnerability", None),
        ("item", "Vulnerability", None),
        ("item", "Vulnerability", None),
        ("member", "tail", {"zero": 0}),
    ]


def test_discarded_object_duplicate_keys_and_cancellation_cleanup(
    monkeypatch, tmp_path
):
    import sqlite3
    from contextlib import contextmanager
    from . import json_stream

    connections = []
    original = json_stream.temporary_index

    @contextmanager
    def temporary():
        with original() as connection:
            connections.append(connection)
            yield connection

    monkeypatch.setattr(json_stream, "temporary_index", temporary)
    for payload in (
        b'{"Vulnerability":[{"a":{"x":1,"x":2}}]}',
        b'{"Vulnerability":[{"a":1,"child":{"a":2},"a":3}]}',
    ):
        with pytest.raises(ValueError, match="Duplicate"):
            list(
                json_stream.document_array(
                    SmallReads(payload), "Vulnerability", materialize_items=False
                )
            )
    iterator = json_stream.document_array(
        SmallReads(b'{"Vulnerability":[{"a":1},{"a":2}]}'),
        "Vulnerability",
        materialize_items=False,
    )
    next(iterator)
    next(iterator)
    iterator.close()
    with pytest.raises(ValueError, match="cancelled"):
        list(
            json_stream.document_array(
                SmallReads(b'{"Vulnerability":[]}'),
                "Vulnerability",
                materialize_items=False,
                cancelled=lambda: True,
            )
        )
    assert len(connections) == 4
    for connection in connections:
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            connection.execute("SELECT 1")


@pytest.mark.parametrize("control", range(32))
def test_unescaped_ascii_controls_never_pass_streaming_validation(control):
    raw = b'{"synthetic":"before' + bytes([control]) + b'after"}'
    with pytest.raises(ValueError):
        list(object_members(SmallReads(raw)))


def test_plain_ascii_at_text_limit_remains_exact():
    from standalone.evidence_pipeline.parsing.public_inputs import MAX_TEXT

    value = "a" * MAX_TEXT
    assert (
        dict(object_members(io.BytesIO(json.dumps({"synthetic": value}).encode())))[
            "synthetic"
        ]
        == value
    )


def test_metadata_pass_cancels_inside_a_large_discarded_item():
    from .json_stream import document_array

    calls = 0

    def cancelled():
        nonlocal calls
        calls += 1
        return calls > 100

    stream = SmallReads(b'{"Vulnerability":[{"items":[' + b"0," * 10000 + b"0]}]}")
    with pytest.raises(ValueError, match="cancelled"):
        list(
            document_array(
                stream, "Vulnerability", materialize_items=False, cancelled=cancelled
            )
        )
    assert stream.tell() < len(stream.getvalue())
