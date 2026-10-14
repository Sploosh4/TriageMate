"""Offline contract tests; persistence is deliberately not implemented."""

import json
from decimal import Decimal, localcontext

import pytest

from standalone.synthetic_epss import ValidationError, fingerprint, parse_payload


def payload(records=None, **changes):
    value = {
        "origin": "synthetic",
        "fixture_id": "triagemate-epss-import-v1",
        "data": records if records is not None else [record()],
    }
    value.update(changes)
    return json.dumps(value).encode()


def record(**changes):
    value = {
        "cve": "CVE-2099-900001",
        "epss": "0.12345678901234567890123456789",
        "date": "2026-09-11",
    }
    value.update(changes)
    return value


def test_exact_decimal_unknown_and_attribution():
    with localcontext() as context:
        context.prec = 3
        result = parse_payload(payload())
    observation = result.observations[0]
    assert observation.probability == Decimal(record()["epss"])
    assert observation.percentile is None and observation.model_version is None
    assert (
        result.origin == "synthetic"
        and result.fixture_id == "triagemate-epss-import-v1"
    )
    assert result.source_scope == "offline-synthetic-epss-v1"
    assert result.observations == parse_payload(payload()).observations


@pytest.mark.parametrize(
    "score", ["0", "1", "0.000", "1.000", "0." + "0" * 16382 + "1"]
)
def test_exact_boundaries(score):
    item = parse_payload(payload([record(epss=score, percentile=score)])).observations[
        0
    ]
    assert item.probability == item.percentile == Decimal(score)


@pytest.mark.parametrize(
    "score",
    [
        0,
        0.5,
        False,
        None,
        "",
        "NaN",
        "Infinity",
        "-0.1",
        "1.01",
        "1e-2",
        " 0.2",
        "0." + "0" * 16384,
    ],
)
def test_rejects_invalid_probability(score):
    with pytest.raises(ValidationError):
        parse_payload(payload([record(epss=score)]))


@pytest.mark.parametrize(
    "changes",
    [
        {"percentile": "1.1"},
        {"percentile": False},
        {"date": "2026-02-30"},
        {"date": "20260911"},
        {"date": None},
        {"cve": "cve-2099-900001"},
        {"cve": "bad"},
        {"model_version": ""},
        {"model_version": 1},
        {"model_version": "\ud800"},
        {"extra": "bad"},
    ],
)
def test_rejects_invalid_record(changes):
    with pytest.raises(ValidationError):
        parse_payload(payload([record(**changes)]))


def test_required_fields_and_top_level_contract():
    for key in ("cve", "epss", "date"):
        item = record()
        del item[key]
        with pytest.raises(ValidationError):
            parse_payload(payload([item]))
    for value in (
        b"[]",
        payload(origin="public"),
        payload(fixture_id=""),
        payload(data={}),
        payload(extra=True),
    ):
        with pytest.raises(ValidationError):
            parse_payload(value)


@pytest.mark.parametrize(
    "raw",
    [
        b"\xff",
        b"{",
        b'{"origin":"synthetic","origin":"synthetic"}',
        b'{"data":NaN}',
        payload().replace(b'"epss":', b'"epss":"0", "epss":'),
    ],
)
def test_malformed_json_and_duplicate_keys(raw):
    with pytest.raises(ValidationError):
        parse_payload(raw)


def test_duplicates_and_all_or_nothing_validation():
    for records in ([record(), record()], [record(), record(cve="invalid")]):
        with pytest.raises(ValidationError):
            parse_payload(payload(records))


def test_empty_success_and_invalid_input_fingerprint():
    assert parse_payload(payload([])).observations == ()
    assert fingerprint(b"invalid") == fingerprint(b"invalid")
    assert fingerprint(b"invalid") != fingerprint(b"invalid ")
    with pytest.raises(TypeError):
        fingerprint("not bytes")


def test_raw_replay_vs_semantic_content():
    a = payload([record(epss="0.20", percentile=None)])
    b = payload([record(epss="0.2")])
    assert parse_payload(a).input_fingerprint != parse_payload(b).input_fingerprint
    assert (
        parse_payload(a).observations[0].content_hash
        == parse_payload(b).observations[0].content_hash
    )
    assert fingerprint(a) != fingerprint(a + b" ")
    assert parse_payload(a).observations == parse_payload(a + b" ").observations
    for changes in (
        {"epss": "0.3"},
        {"percentile": "0.3"},
        {"date": "2026-09-12"},
        {"model_version": "provided-v1"},
    ):
        assert (
            parse_payload(a).observations[0].content_hash
            != parse_payload(payload([record(**changes)])).observations[0].content_hash
        )
    assert (
        parse_payload(a).observations[0].content_hash
        != parse_payload(payload([record(epss="0.2")], fixture_id="another-fixture"))
        .observations[0]
        .content_hash
    )


def test_order_and_explicit_model():
    a, b = record(model_version="synthetic-v1"), record(cve="CVE-2099-900002", epss="0")
    assert (
        parse_payload(payload([a, b])).observations
        == parse_payload(payload([b, a])).observations
    )
    assert parse_payload(payload([a])).observations[0].model_version == "synthetic-v1"


def test_checked_in_fixture_is_processed():
    from pathlib import Path

    raw = (Path(__file__).parent / "fixtures/synthetic_epss_v1.json").read_bytes()
    parsed = parse_payload(raw)
    assert len(parsed.observations) == 2
    assert parsed.observations[0].percentile == Decimal("0.75")
    assert parsed.observations[1].probability == Decimal("0")
    assert parsed.observations[1].percentile is None
    changed = raw.replace(b'"0.75"', b'"0.76"')
    assert parse_payload(changed).observations[0].percentile == Decimal("0.76")
    assert parse_payload(changed).input_fingerprint != parsed.input_fingerprint
