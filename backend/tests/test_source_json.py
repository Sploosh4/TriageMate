"""Retained source serialization must not change evidence identity."""

from decimal import Decimal
import json

import pytest

from standalone.evidence_pipeline.source_json import (
    encode_source_records,
    encode_source_text,
)
from standalone.evidence_pipeline.parsing.cve_records import source_json


def legacy(value):
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ValueError("Nonfinite source number")
        return str(value)
    if isinstance(value, dict):
        return (
            "{"
            + ",".join(
                json.dumps(key, ensure_ascii=False) + ":" + legacy(item)
                for key, item in value.items()
            )
            + "}"
        )
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(legacy(item) for item in value) + "]"
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))


def ordered(value):
    if isinstance(value, dict):
        return {key: ordered(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        return [ordered(item) for item in value]
    return value


@pytest.mark.parametrize(
    "value",
    [
        {},
        [],
        None,
        False,
        0,
        -0.0,
        Decimal("1.23000000000000000001"),
        {"z": [Decimal("1E+99"), {"b": '🐍\\"\n', "a": False}], "a": None},
        {"z": ({"b": 1, "a": [{"z": 2, "a": 1}]},), "a": [0, True]},
        {
            "synthetic": [
                {
                    "description": "Synthetic issue " * 1000,
                    "releases": {"z": 0, "a": False},
                }
            ]
            * 300
        },
    ],
)
def test_exact_legacy_wire_and_sorted_claim(value):
    assert encode_source_records(value) == legacy(value).encode()
    assert source_json(value) == legacy(ordered(value))


@pytest.mark.parametrize(
    "value",
    [
        Decimal("NaN"),
        Decimal("Infinity"),
        float("nan"),
        float("inf"),
        {1: "invalid key"},
        {"nested": [Decimal("-Infinity")]},
    ],
)
def test_reject_invalid_source_values(value):
    with pytest.raises(ValueError):
        encode_source_records(value)
    with pytest.raises(ValueError):
        encode_source_text(value, sort_keys=True)


def test_reused_encoder_does_not_leak_state_after_failure_or_between_threads():
    from concurrent.futures import ThreadPoolExecutor

    def encode_pair(index):
        with pytest.raises(ValueError):
            encode_source_records({"invalid": float("nan")})
        value = {"z": [index, Decimal("0.1234567890123456789")], "a": '雪\\"\n'}
        return (
            encode_source_records(value) == legacy(value).encode(),
            encode_source_text(value, sort_keys=True) == legacy(ordered(value)),
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert all(all(results) for results in pool.map(encode_pair, range(64)))
