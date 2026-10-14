"""Synthetic CVE and ADP facts remain independent, including unknown and rejected states."""

from dataclasses import replace
from decimal import Decimal
import json
from uuid import uuid4

import pytest

from .contracts import SourceScope
from standalone.evidence_pipeline.parsing.cve_program import parse_cve_record


def scope():
    return SourceScope(
        str(uuid4()),
        "CVE",
        "records",
        "synthetic-cve-record",
        "synthetic",
        "TriageMate generated synthetic CVE JSON fixture",
    )


def document():
    return {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.2.0",
        "cveMetadata": {
            "cveId": "CVE-2099-12345",
            "assignerOrgId": str(uuid4()),
            "state": "PUBLISHED",
            "datePublished": "2026-09-14T01:02:03.123456789",
        },
        "containers": {
            "cna": {
                "providerMetadata": {
                    "orgId": str(uuid4()),
                    "shortName": "Synthetic-CNA",
                },
                "descriptions": [
                    {"lang": "en", "value": "Synthetic vulnerability description"}
                ],
                "references": [{"url": "https://example.invalid/synthetic-advisory"}],
                "affected": [
                    {
                        "vendor": "Synthetic vendor",
                        "product": "Synthetic package",
                        "packageURL": "pkg:generic/synthetic-package",
                        "defaultStatus": "unknown",
                        "versions": [
                            {
                                "version": "1.0",
                                "status": "affected",
                                "versionType": "custom",
                                "lessThan": "2.0",
                                "changes": [{"at": "1.5", "status": "unaffected"}],
                            }
                        ],
                    }
                ],
                "tags": ["disputed"],
            },
            "adp": [
                {
                    "providerMetadata": {
                        "orgId": str(uuid4()),
                        "shortName": "Synthetic-ADP",
                    },
                    "metrics": [
                        {
                            "other": {
                                "type": "ssvc",
                                "content": {"options": [{"Exploitation": "none"}]},
                            }
                        }
                    ],
                }
            ],
        },
    }


def parse(value):
    return parse_cve_record(json.dumps(value).encode(), scope=scope()).records[0]


@pytest.mark.parametrize("version", ["5.0", "5.1", "5.1.1", "5.2", "5.2.0"])
def test_supported_wire_versions_preserve_the_publishers_spelling(version):
    value = document()
    value["dataVersion"] = version
    assert parse(value).data_version == version


def test_cna_adp_and_affected_ranges_are_not_merged_or_reinterpreted():
    value = document()
    record = parse(value)
    assert record.state == "PUBLISHED" and record.data_version == "5.2.0"
    cna, adp = record.contributions
    assert cna.kind == "cna" and adp.kind == "adp"
    assert cna.organization_id != adp.organization_id
    assert cna.raw == value["containers"]["cna"]
    assert adp.raw == value["containers"]["adp"][0]
    assert record.metadata["datePublished"] == "2026-09-14T01:02:03.123456789"


def test_rejected_cve_keeps_reason_and_replacement_without_becoming_a_fix():
    value = document()
    value["cveMetadata"]["state"] = "REJECTED"
    value["containers"] = {
        "cna": {
            "providerMetadata": {"orgId": str(uuid4())},
            "rejectedReasons": [
                {"lang": "en", "value": "Synthetic duplicate assignment"}
            ],
            "replacedBy": ["CVE-2099-54321"],
        }
    }
    record = parse(value)
    assert record.state == "REJECTED"
    assert record.contributions[0].raw["replacedBy"] == ["CVE-2099-54321"]
    assert "affected" not in record.contributions[0].raw


@pytest.mark.parametrize(
    "damage",
    [
        "version",
        "state",
        "identity",
        "missing_cna",
        "range",
        "status",
        "time",
        "wrong_type",
    ],
)
def test_malformed_claims_are_rejected_as_input_errors(damage):
    value = document()
    if damage == "version":
        value["dataVersion"] = "5.99"
    elif damage == "state":
        value["cveMetadata"]["state"] = "RESERVED"
    elif damage == "identity":
        value["cveMetadata"]["assignerOrgId"] = "not-a-uuid"
    elif damage == "missing_cna":
        del value["containers"]["cna"]
    elif damage == "time":
        value["cveMetadata"]["datePublished"] = "2026-02-30T00:00:00Z"
    elif damage == "wrong_type":
        value["dataVersion"] = []
    else:
        version = value["containers"]["cna"]["affected"][0]["versions"][0]
        if damage == "range":
            version["lessThanOrEqual"] = "2.1"
        else:
            version["status"] = []
    with pytest.raises(ValueError):
        parse(value)


def test_cisa_input_retains_other_contributors_without_relabelling_their_work():
    value = document()
    source = replace(scope(), source="CISA", input_kind="vulnrichment")
    record = parse_cve_record(json.dumps(value).encode(), scope=source).records[0]
    assert [item.provider_name for item in record.contributions] == [
        "Synthetic-CNA",
        "Synthetic-ADP",
    ]


def test_raw_metric_precision_is_preserved():
    wire = (
        json.dumps(document())
        .encode()
        .replace(b'"dataType":', b'"x_metric":0.1234567890123456789,"dataType":', 1)
    )
    feed = parse_cve_record(wire, scope=scope())
    assert feed.raw_payload == wire
    value = document()
    value["containers"]["adp"][0]["metrics"] = [
        {"other": {"type": "synthetic", "content": {"value": 1}}}
    ]
    wire = (
        json.dumps(value)
        .encode()
        .replace(b'"value": 1', b'"value": 0.1234567890123456789')
    )
    record = parse_cve_record(wire, scope=scope()).records[0]
    assert record.contributions[1].raw["metrics"][0]["other"]["content"][
        "value"
    ] == Decimal("0.1234567890123456789")


def test_duplicate_keys_and_private_scope_are_rejected():
    with pytest.raises(ValueError):
        parse_cve_record(
            b'{"dataType":"CVE_RECORD","dataType":"CVE_RECORD"}', scope=scope()
        )
    with pytest.raises(ValueError):
        parse_cve_record(
            json.dumps(document()).encode(),
            scope=replace(scope(), tenant_id=str(uuid4())),
        )
