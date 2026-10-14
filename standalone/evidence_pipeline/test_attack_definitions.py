"""Synthetic ATT&CK definitions remain independent of vulnerability mappings."""

import json
from uuid import uuid4

import pytest

from standalone.evidence_pipeline.parsing import attack_definitions as source
from .contracts import SourceScope


def scope():
    return SourceScope(
        str(uuid4()),
        "MITRE ATT&CK",
        "enterprise_definitions",
        source.URL,
        "synthetic",
        "TriageMate generated synthetic ATT&CK bundle",
    )


def definition(**changes):
    return dict(
        dict(
            type="attack-pattern",
            id="attack-pattern--" + str(uuid4()),
            spec_version="2.1",
            created="2099-01-01T00:00:00Z",
            modified="2099-01-02T00:00:00Z",
            name="Synthetic technique",
            external_references=[
                dict(source_name="mitre-attack", external_id="T1059.001")
            ],
        ),
        **changes,
    )


def payload(objects):
    return json.dumps(
        dict(type="bundle", id="bundle--" + str(uuid4()), objects=objects)
    ).encode()


def test_definition_keeps_revocation_and_creates_no_cve_mapping():
    obj = definition(
        revoked=True, x_mitre_deprecated=True, x_mitre_is_subtechnique=True
    )
    feed = source.parse_attack(payload([obj]), scope=scope())
    record = feed.records[0]
    assert record.source_record_id == obj["id"] and record.technique_ids == (
        "T1059.001",
    )
    assert record.raw == obj and record.cve_ids == ()


def test_collection_metadata_and_external_references_do_not_create_mappings():
    obj = definition(
        external_references=[dict(source_name="CVE", external_id="CVE-2099-1234")]
    )
    collection = dict(
        type="x-mitre-collection",
        name="Synthetic collection",
        x_mitre_version="synthetic",
        x_mitre_contents=[],
    )
    feed = source.parse_attack(
        payload([collection, obj, dict(type="relationship")]), scope=scope()
    )
    assert (
        len(feed.records) == 1
        and not feed.records[0].technique_ids
        and not feed.records[0].cve_ids
    )
    assert feed.metadata["collections"] == [
        {key: value for key, value in collection.items() if key != "x_mitre_contents"}
    ]


@pytest.mark.parametrize(
    "changes",
    [
        dict(id="attack-pattern--bad"),
        dict(spec_version="2.0"),
        dict(revoked="false"),
        dict(modified="invalid"),
        dict(name=""),
        dict(
            external_references=[
                dict(source_name="mitre-attack", external_id="CVE-2099-1234")
            ]
        ),
    ],
)
def test_invalid_definition_rejected(changes):
    with pytest.raises(ValueError):
        source.parse_attack(payload([definition(**changes)]), scope=scope())


def test_multiple_versions_preserved_but_duplicate_version_rejected():
    first = definition()
    second = dict(first, modified="2099-01-03T00:00:00Z", revoked=True)
    assert (
        len(source.parse_attack(payload([first, second]), scope=scope()).records) == 2
    )
    with pytest.raises(ValueError):
        source.parse_attack(payload([first, first]), scope=scope())


def test_payload_above_frontend_budget():
    wire = b" " * 45_000_001 + payload([definition()])
    assert len(source.parse_attack(wire, scope=scope()).records) == 1
