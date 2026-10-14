"""Streamed MSRC claims preserve byte-path identities and rejection behavior."""

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
from uuid import uuid4

import pytest

from standalone.evidence_pipeline.parsing.cvrf_stream import StreamedCvrfUpdates
from standalone.evidence_pipeline.parsing.cvrf_updates import parse_cvrf_updates
from .file_payload import FilePayload
from standalone.evidence_pipeline.parsing.public_records import normalize_public
from standalone.evidence_pipeline.parsing.public_snapshot import PublicSnapshot
from .test_cvrf_updates import document, source


def saved(tmp_path, payload):
    path = tmp_path / "cvrf.json"
    path.write_bytes(payload)
    path.chmod(0o600)
    return FilePayload(path, hashlib.sha256(payload).hexdigest())


@pytest.mark.parametrize(
    "variant", ["ordinary", "empty", "no_fix", "cycle", "reordered"]
)
def test_streamed_claims_match_existing_byte_path(tmp_path, variant):
    value = document()
    if variant == "empty":
        value["Vulnerability"] = []
    elif variant == "no_fix":
        value["Vulnerability"][0]["Remediations"] = []
    elif variant == "cycle":
        value["Vulnerability"][0]["Remediations"].append(
            {
                "Type": 2,
                "ProductID": ["p1"],
                "Description": {"Value": "9999990"},
                "Supercedence": "9999991",
            }
        )
    elif variant == "reordered":
        later = dict(value["Vulnerability"][0], CVE="CVE-2026-12344")
        value = {
            "Vulnerability": [value["Vulnerability"][0], later],
            "ProductTree": value["ProductTree"],
            "Extension": {"zero": 0, "flag": False},
        }
    payload = json.dumps(value).encode()
    scope = source()
    streamed = StreamedCvrfUpdates(scope, saved(tmp_path, payload))
    original = parse_cvrf_updates(payload, scope=scope)
    assert sorted(streamed.records, key=repr) == sorted(original.records, key=repr)
    assert sorted(normalize_public(streamed), key=lambda r: r.cve_id) == sorted(
        normalize_public(original), key=lambda r: r.cve_id
    )


@pytest.mark.parametrize(
    "damage", ["duplicate", "unknown_product", "bad_tail", "bad_cve"]
)
def test_invalid_later_record_cannot_form_a_complete_snapshot(tmp_path, damage):
    value = document()
    second = dict(value["Vulnerability"][0], CVE="CVE-2026-12346")
    if damage == "duplicate":
        second["CVE"] = value["Vulnerability"][0]["CVE"]
    elif damage == "unknown_product":
        second["ProductStatuses"] = [{"Type": 3, "ProductID": ["unknown"]}]
    elif damage == "bad_cve":
        second["CVE"] = "not-a-cve"
    value["Vulnerability"].append(second)
    payload = json.dumps(value).encode()
    if damage == "bad_tail":
        payload = payload[:-1]
    now = datetime.now(timezone.utc)
    with pytest.raises(ValueError):
        PublicSnapshot(
            source(), str(uuid4()), now, now, "success", True, saved(tmp_path, payload)
        )


def test_global_relationship_bound_is_not_reset_for_each_cve(tmp_path, monkeypatch):
    from standalone.evidence_pipeline.parsing import cvrf_stream

    value = document()
    value["Vulnerability"].append(dict(value["Vulnerability"][0], CVE="CVE-2026-12346"))
    monkeypatch.setattr(cvrf_stream, "MAX_PUBLIC_RECORDS", 3)
    feed = StreamedCvrfUpdates(source(), saved(tmp_path, json.dumps(value).encode()))
    with pytest.raises(ValueError, match="relationship bound"):
        list(feed.records)


def test_collection_and_saved_replay_use_file_payload(tmp_path):
    from standalone.evidence_pipeline.collection.public_collection import prepare
    from standalone.evidence_pipeline.collection.public_transport import endpoint

    scope = replace(
        source(),
        scope_reference=endpoint(
            "MSRC", month="2026-Sep", input_kind="security_updates"
        ),
    )
    run = str(uuid4())
    bundle = tmp_path / "bundle"
    first = prepare(
        scope,
        run,
        bundle,
        month="2026-Sep",
        synthetic_payload=json.dumps(document()).encode(),
    )
    assert first.complete and isinstance(first.payload, FilePayload)
    replay = prepare(scope, run, bundle, month="2026-Sep", replay_only=True)
    assert list(normalize_public(first.feed())) == list(normalize_public(replay.feed()))


def test_early_stop_closes_temporary_cve_index(tmp_path, monkeypatch):
    import sqlite3
    from contextlib import contextmanager
    from standalone.evidence_pipeline.parsing import cvrf_stream

    connections = []
    original = cvrf_stream.temporary_index

    @contextmanager
    def temporary():
        with original() as connection:
            connections.append(connection)
            yield connection

    monkeypatch.setattr(cvrf_stream, "temporary_index", temporary)
    iterator = cvrf_stream.documents(
        saved(tmp_path, json.dumps(document()).encode()), source()
    )
    next(iterator)
    assert connections and connections[0].execute(
        "SELECT count(*) FROM cves"
    ).fetchone() == (1,)
    iterator.close()
    for connection in connections:
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            connection.execute("SELECT 1")


def test_spooled_values_preserve_exact_decimal_and_literal_tag_objects(tmp_path):
    value = document()
    value["Vulnerability"][0]["Extension"] = {
        "exact": "DECIMAL_TOKEN",
        "literal": {"decimal": "not-a-number"},
        "false": False,
        "zero": 0,
    }
    payload = (
        json.dumps(value)
        .replace('"DECIMAL_TOKEN"', "0.12345678901234567890123456789")
        .encode()
    )
    chosen = source()
    actual = list(
        normalize_public(StreamedCvrfUpdates(chosen, saved(tmp_path, payload)))
    )
    expected = list(normalize_public(parse_cvrf_updates(payload, scope=chosen)))
    assert actual == expected


@pytest.mark.parametrize("failure", ["close", "malformed_tail", "bad_product"])
def test_private_spool_closes_on_stop_or_rejection(tmp_path, monkeypatch, failure):
    import sqlite3
    from standalone.evidence_pipeline.parsing import cvrf_stream

    original = cvrf_stream.VerificationSpool
    opened = []

    class TrackedSpool(original):
        def __enter__(self):
            result = super().__enter__()
            opened.append(result.connection)
            return result

    monkeypatch.setattr(cvrf_stream, "VerificationSpool", TrackedSpool)
    value = document()
    if failure == "bad_product":
        value["Vulnerability"][0]["ProductStatuses"][0]["ProductID"] = ["missing"]
    payload = json.dumps(value).encode()
    if failure == "malformed_tail":
        payload = payload[:-1]
    iterator = cvrf_stream.documents(saved(tmp_path, payload), source())
    if failure == "close":
        next(iterator)
        iterator.close()
    else:
        with pytest.raises(ValueError):
            next(iterator)
    assert len(opened) == 1
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        opened[0].execute("SELECT 1")


def empty_publication():
    return {
        "DocumentTitle": {"Value": "Synthetic empty publication"},
        "DocumentType": {"Value": "Security Update"},
        "DocumentPublisher": {"Type": 0},
        "DocumentTracking": {
            "Identification": {"ID": {"Value": "2017-May-B"}},
            "Version": "1.0",
            "InitialReleaseDate": "2017-05-08T07:00:00",
            "CurrentReleaseDate": "2017-05-08T07:00:00",
        },
        "ProductTree": {"Branch": [{"Type": 0, "Name": "Synthetic publisher"}]},
    }


@pytest.mark.parametrize(
    "damage",
    [None, "identity", "header", "null_array", "null_products", "tail", "duplicate"],
)
def test_empty_publication_requires_complete_identified_envelope(tmp_path, damage):
    value = empty_publication()
    scope = replace(
        source(),
        scope_reference="https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2017-May-B",
    )
    if damage == "identity":
        value["DocumentTracking"]["Identification"]["ID"]["Value"] = "2017-May"
    elif damage == "header":
        del value["DocumentTitle"]
    elif damage == "null_array":
        value["Vulnerability"] = None
    elif damage == "null_products":
        value["ProductTree"]["FullProductName"] = None
    payload = json.dumps(value).encode()
    if damage == "tail":
        payload = payload[:-1]
    elif damage == "duplicate":
        payload = payload[:-1] + b',"DocumentTitle":{"Value":"duplicate"}}'

    def both():
        original = parse_cvrf_updates(payload, scope=scope)
        assert list(normalize_public(original)) == []
        assert (
            list(normalize_public(StreamedCvrfUpdates(scope, saved(tmp_path, payload))))
            == []
        )

    if damage is None:
        both()
    else:
        with pytest.raises(ValueError):
            parse_cvrf_updates(payload, scope=scope)
        with pytest.raises(ValueError):
            list(normalize_public(StreamedCvrfUpdates(scope, saved(tmp_path, payload))))


@pytest.mark.parametrize(
    "damage", ["duplicate_identity", "missing_name", "wrong_scope"]
)
def test_product_metadata_after_records_is_still_validated(tmp_path, damage):
    value = document()
    scope = source()
    if damage == "duplicate_identity":
        value["ProductTree"]["FullProductName"].append(
            dict(value["ProductTree"]["FullProductName"][0])
        )
    elif damage == "missing_name":
        value["ProductTree"]["FullProductName"][0].pop("Value")
    else:
        scope = replace(scope, source="Other")
    value = {
        "Vulnerability": value["Vulnerability"],
        "ProductTree": value["ProductTree"],
    }
    feed = StreamedCvrfUpdates(scope, saved(tmp_path, json.dumps(value).encode()))
    with pytest.raises(ValueError):
        next(iter(normalize_public(feed)))
