"""Explicitly synthetic public-source wire fixtures; no external feed access."""

from dataclasses import FrozenInstanceError, replace
from datetime import date, timezone
from decimal import Decimal
import json

import pytest

from .contracts import SourceScope
from standalone.evidence_pipeline.parsing import public_inputs as parser


CVE = "CVE-2026-9999999"  # Synthetic identifier, never an assertion about a real CVE.


def scope(source):
    return SourceScope(
        "10000000-0000-4000-8000-000000000001",
        source,
        parser.INPUT_KINDS[source],
        "https://example.invalid/synthetic-feed",
        "synthetic",
        "Explicitly synthetic TriageMate parser test; no real vulnerability claims",
    )


def wire(value):
    return json.dumps(value).encode()


def epss(row=None):
    return (
        "#model_version:synthetic-v1,score_date:2026-09-12\n"
        "cve,epss,percentile\n" + (row or f"{CVE},0.12345678901234567890123456789,0\n")
    ).encode()


def kev():
    return {
        "catalogVersion": "synthetic-1",
        "dateReleased": "2026-09-12T00:00:00Z",
        "count": 1,
        "vulnerabilities": [
            {
                "cveID": CVE,
                "vendorProject": "Synthetic",
                "product": "Fixture",
                "vulnerabilityName": "Synthetic fixture",
                "shortDescription": "Synthetic only",
                "requiredAction": "Synthetic source recommendation",
                "dateAdded": "2026-09-11",
                "dueDate": "2026-09-14",
                "knownRansomwareCampaignUse": "Unknown",
                "notes": "",
                "cwes": ["CWE-79"],
                "futureField": {"unknown": [False, None]},
            }
        ],
    }


def metric(version="3.1", source="synthetic@example.invalid", score=9.8):
    vector = {
        "2.0": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
        "3.0": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "3.1": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "4.0": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    }[version]
    return {
        "source": source,
        "type": "Primary",
        "cvssData": {
            "version": version,
            "baseScore": score,
            "vectorString": vector,
            "baseSeverity": "CRITICAL",
        },
    }


def nvd():
    return {
        "format": "NVD_CVE",
        "version": "2.0",
        "timestamp": "2026-09-12T03:00:00.123",
        "startIndex": 0,
        "totalResults": 1,
        "resultsPerPage": 1,
        "vulnerabilities": [
            {
                "cve": {
                    "id": CVE,
                    "sourceIdentifier": "synthetic@example.invalid",
                    "published": "2026-09-10T01:00:00.000",
                    "lastModified": "2026-09-11T02:00:00.000",
                    "vulnStatus": "Analyzed",
                    "descriptions": [{"lang": "en", "value": "Synthetic CVE"}],
                    "references": [
                        {
                            "url": "https://example.invalid/synthetic-advisory",
                            "source": "synthetic@example.invalid",
                            "tags": ["Vendor Advisory"],
                        }
                    ],
                    "metrics": {
                        key: [metric(version)]
                        for key, version in parser.VERSIONS.items()
                    },
                    "futureField": {"unknown": [False, None]},
                }
            }
        ],
    }


def test_epss_exact_decimal_zero_metadata_and_immutability():
    feed = parser.parse_epss_csv(epss(), scope=scope("FIRST"))
    assert feed.score_date == date(2026, 9, 12)
    assert feed.model_version == "synthetic-v1"
    assert feed.records[0].probability == Decimal("0.12345678901234567890123456789")
    assert feed.records[0].percentile == Decimal(0)
    assert feed.raw_payload == epss()
    assert len(feed.input_fingerprint) == 64
    with pytest.raises(FrozenInstanceError):
        feed.records[0].probability = Decimal(1)


def test_epss_old_header_requires_explicit_date_and_unknown_model():
    payload = f"cve,epss,percentile\n{CVE},0,1\n".encode()
    with pytest.raises(ValueError):
        parser.parse_epss_csv(payload, scope=scope("FIRST"))
    feed = parser.parse_epss_csv(
        payload, scope=scope("FIRST"), score_date=date(2021, 4, 14)
    )
    assert feed.model_version is None
    assert feed.records[0].percentile == Decimal(1)


@pytest.mark.parametrize(
    "payload",
    [
        epss(f"{CVE},NaN,0\n"),
        epss(f"{CVE},1.0001,0\n"),
        epss(f"{CVE},-0.1,0\n"),
        epss(f"{CVE},0,-1\n"),
        epss(f"{CVE},,0\n"),
        epss(f"{CVE},0,1,extra\n"),
        epss(f"{CVE},0,1\n{CVE},0,1\n"),
        epss('"unterminated,0,1\n'),
        epss("not-a-cve,0,1\n"),
        epss().replace(b"score_date:2026-09-12", b"score_date:2026-02-30"),
        epss().replace(
            b"score_date:2026-09-12", b"score_date:2026-09-12,score_date:2026-09-12"
        ),
        epss().replace(b"cve,epss,percentile", b"cve,epss,epss"),
        epss() + b"\n",
    ],
)
def test_epss_rejects_whole_input_on_invalid_rows(payload):
    with pytest.raises(ValueError):
        parser.parse_epss_csv(payload, scope=scope("FIRST"))


def test_epss_conflicting_date_rejected():
    with pytest.raises(ValueError):
        parser.parse_epss_csv(
            epss(), scope=scope("FIRST"), score_date=date(2026, 9, 11)
        )


def test_kev_preserves_membership_source_action_dates_and_unknown():
    payload = wire(kev())
    feed = parser.parse_kev_json(payload, scope=scope("CISA"))
    record = feed.records[0]
    assert record.is_member is True
    assert record.required_action == "Synthetic source recommendation"
    assert record.date_added == date(2026, 9, 11)
    assert record.due_date == date(2026, 9, 14)
    assert record.known_ransomware_campaign_use == "Unknown"
    assert record.notes == ""
    assert record.cwes == ("CWE-79",)
    assert feed.coverage == "catalogue"
    assert feed.raw_payload == payload  # Includes unknown future fields intact.


@pytest.mark.parametrize(
    "field,value",
    [
        ("cveID", "CVE-2026-x"),
        ("dateAdded", "2026-02-30"),
        ("dueDate", "20260914"),
        ("requiredAction", None),
        ("product", 42),
        ("cwes", ["BAD"]),
    ],
)
def test_kev_invalid_record_rejects_catalogue(field, value):
    document = kev()
    document["vulnerabilities"][0][field] = value
    with pytest.raises(ValueError):
        parser.parse_kev_json(wire(document), scope=scope("CISA"))


@pytest.mark.parametrize("change", ["count", "duplicate", "release", "missing"])
def test_kev_rejects_ambiguous_or_incomplete_catalogue(change):
    document = kev()
    if change == "count":
        document["count"] = 2
    elif change == "duplicate":
        document["vulnerabilities"] *= 2
        document["count"] = 2
    elif change == "release":
        document["dateReleased"] = "2026-09-12T00:00:00"
    else:
        del document["vulnerabilities"]
    with pytest.raises(ValueError):
        parser.parse_kev_json(wire(document), scope=scope("CISA"))


def test_nvd_retains_all_versions_and_disagreeing_publishers_and_details():
    document = nvd()
    document["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"].append(
        metric(source="another-synthetic@example.invalid", score=7.2)
    )
    payload = wire(document)
    feed = parser.parse_nvd_json(payload, scope=scope("NVD"))
    record = feed.records[0]
    assert len(record.assessments) == 5
    assert {item.version for item in record.assessments} == {"2.0", "3.0", "3.1", "4.0"}
    assert {item.score for item in record.assessments} == {
        Decimal("9.8"),
        Decimal("7.2"),
    }
    assert record.descriptions[0].value == "Synthetic CVE"
    assert record.references[0].tags == ("Vendor Advisory",)
    assert record.published.tzinfo is timezone.utc
    assert record.last_modified.hour == 2
    assert feed.coverage == "query"
    assert feed.raw_payload == payload


def test_nvd_missing_optional_facts_remain_unknown_and_no_metrics_is_not_zero():
    document = nvd()
    document["vulnerabilities"][0]["cve"] = {"id": CVE}
    record = parser.parse_nvd_json(wire(document), scope=scope("NVD")).records[0]
    assert record.published is record.last_modified is record.source_identifier is None
    assert record.assessments == record.descriptions == record.references == ()


def test_empty_feed_is_not_an_invented_negative_record():
    document = nvd()
    document.update(vulnerabilities=[], totalResults=0, resultsPerPage=0)
    assert parser.parse_nvd_json(wire(document), scope=scope("NVD")).records == ()
    document = kev()
    document.update(vulnerabilities=[], count=0)
    assert parser.parse_kev_json(wire(document), scope=scope("CISA")).records == ()


@pytest.mark.parametrize(
    "key,value",
    [
        ("startIndex", 1),
        ("totalResults", 2),
        ("resultsPerPage", 0),
        ("totalResults", True),
        ("format", "other"),
        ("timestamp", "bad"),
    ],
)
def test_nvd_incomplete_or_invalid_envelope_rejected(key, value):
    document = nvd()
    document[key] = value
    with pytest.raises(ValueError):
        parser.parse_nvd_json(wire(document), scope=scope("NVD"))


@pytest.mark.parametrize(
    "key,value",
    [
        ("baseScore", True),
        ("baseScore", "9.8"),
        ("baseScore", -1),
        ("baseScore", 11),
        ("version", "3.0"),
        ("vectorString", "CVSS:4.0/no"),
    ],
)
def test_nvd_invalid_assessment_rejects_result(key, value):
    document = nvd()
    document["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"][
        key
    ] = value
    with pytest.raises(ValueError):
        parser.parse_nvd_json(wire(document), scope=scope("NVD"))


@pytest.mark.parametrize("change", ["cve", "assessment", "future", "reference", "date"])
def test_nvd_duplicate_or_malformed_evidence_rejected(change):
    document = nvd()
    record = document["vulnerabilities"][0]["cve"]
    if change == "cve":
        document["vulnerabilities"] *= 2
        document.update(totalResults=2, resultsPerPage=2)
    elif change == "assessment":
        record["metrics"]["cvssMetricV31"] *= 2
    elif change == "future":
        record["metrics"]["cvssMetricV99"] = []
    elif change == "reference":
        record["references"][0]["url"] = "javascript:alert(1)"
    else:
        record["published"] = "2026-02-30T00:00:00"
    with pytest.raises(ValueError):
        parser.parse_nvd_json(wire(document), scope=scope("NVD"))


@pytest.mark.parametrize(
    "payload",
    [
        b'{"count":1,"count":1}',
        b'{"value":NaN}',
        b'{"nested":{"a":1,"a":2}}',
        b"{} trailing",
        b"\xff",
        b"[]",
        b'{"x":"\\ud800"}',
        b'{"x":"\\u0000"}',
    ],
)
@pytest.mark.parametrize(
    "function,source", [(parser.parse_kev_json, "CISA"), (parser.parse_nvd_json, "NVD")]
)
def test_json_strictness(function, source, payload):
    with pytest.raises(ValueError):
        function(payload, scope=scope(source))


def test_bounds_scope_and_deep_unknown_json(monkeypatch):
    with pytest.raises(ValueError):
        parser.parse_epss_csv(epss(), scope=scope("CISA"))
    document = kev()
    document["future"] = json.loads("[" * 70 + "0" + "]" * 70)
    with pytest.raises(ValueError):
        parser.parse_kev_json(wire(document), scope=scope("CISA"))
    monkeypatch.setattr(parser, "MAX_PUBLIC_RECORDS", 0)
    with pytest.raises(ValueError):
        parser.parse_epss_csv(epss(), scope=scope("FIRST"))


@pytest.mark.parametrize(
    "function,source,payload",
    [
        (parser.parse_epss_csv, "FIRST", epss()),
        (parser.parse_kev_json, "CISA", wire(kev())),
        (parser.parse_nvd_json, "NVD", wire(nvd())),
    ],
)
def test_wrong_input_kind_is_rejected(function, source, payload):
    with pytest.raises(ValueError):
        function(payload, scope=replace(scope(source), input_kind="wrong-kind"))


def test_nvd_ssvc_is_retained_but_not_treated_as_cvss():
    document = nvd()
    document["vulnerabilities"][0]["cve"]["metrics"]["ssvcV203"] = [{"synthetic": True}]
    payload = wire(document)
    feed = parser.parse_nvd_json(payload, scope=scope("NVD"))
    assert feed.records[0].supplemental_metric_families == ("ssvcV203",)
    assert len(feed.records[0].assessments) == 4
    assert feed.raw_payload == payload


def test_epss_timestamp_header_keeps_timestamp_and_day():
    payload = epss().replace(
        b"score_date:2026-09-12", b"score_date:2026-09-12T12:00:21Z"
    )
    feed = parser.parse_epss_csv(payload, scope=scope("FIRST"))
    assert feed.score_date == date(2026, 9, 12)
    assert feed.score_timestamp.isoformat() == "2026-09-12T12:00:21+00:00"
    assert feed.raw_payload == payload


def test_epss_scientific_notation_remains_exact():
    feed = parser.parse_epss_csv(epss(f"{CVE},6e-4,7e-05\n"), scope=scope("FIRST"))
    assert feed.records[0].probability == Decimal("0.0006")
    assert feed.records[0].percentile == Decimal("0.00007")


def test_text_scanner_preserves_control_and_unicode_boundaries():
    # Every disallowed control/surrogate remains rejected, including inside text.
    forbidden = [*range(32), *range(0xD800, 0xE000)]
    for code in forbidden:
        value = "synthetic" + chr(code) + "source"
        if code in (9, 10, 13):
            assert parser._text(value) == value
        else:
            with pytest.raises(ValueError, match="Expected bounded text"):
                parser._text(value)
    # Exercise all other Unicode code points in bounded strings; do not narrow
    # accepted source languages, astral characters, DEL or Unicode separators.
    valid = (chr(code) for code in range(32, 0x110000) if not 0xD800 <= code <= 0xDFFF)
    from itertools import islice

    while chunk := "".join(islice(valid, 50000)):
        assert parser._text(chunk) == chunk
    assert parser._text("", empty=True) == ""
    assert parser._text(None, optional=True) is None
    with pytest.raises(ValueError):
        parser._text(" " * 5)
    with pytest.raises(ValueError):
        parser._text("x" * (parser.MAX_TEXT + 1))


@pytest.mark.parametrize("offset", ["+00:60", "-00:60", "+01:99", "+24:00"])
@pytest.mark.parametrize("source", ["CISA", "NVD", "FIRST"])
def test_invalid_timezone_offset_cannot_shift_public_source_dates(source, offset):
    stamp = "2026-09-12T00:00:00" + offset
    if source == "CISA":
        value = kev()
        value["dateReleased"] = stamp
        parse = parser.parse_kev_json
        payload = wire(value)
    elif source == "NVD":
        value = nvd()
        value["timestamp"] = stamp
        parse = parser.parse_nvd_json
        payload = wire(value)
    else:
        parse = parser.parse_epss_csv
        payload = epss().replace(b"2026-09-12", stamp.encode())
    with pytest.raises(ValueError):
        parse(payload, scope=scope(source))


@pytest.mark.parametrize("offset", ["+00:00", "+00:59", "-00:59", "+23:59", "-23:59"])
def test_valid_timezone_offset_preserves_utc_conversion(offset):
    from datetime import datetime

    stamp = "2026-09-12T00:00:00" + offset
    value = kev()
    value["dateReleased"] = stamp
    result = parser.parse_kev_json(wire(value), scope=scope("CISA"))
    assert result.date_released == datetime.fromisoformat(stamp).astimezone(
        timezone.utc
    )
