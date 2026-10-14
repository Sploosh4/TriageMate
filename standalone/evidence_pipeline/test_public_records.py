"""Synthetic relational projections preserve independent public source claims."""

from dataclasses import replace
from decimal import Decimal
import json

from standalone.evidence_pipeline.parsing.public_inputs import (
    parse_epss_csv,
    parse_kev_json,
    parse_nvd_json,
)
from standalone.evidence_pipeline.parsing.public_records import normalize_public
from .test_public_inputs import CVE, epss, kev, nvd, scope, wire

RECEIPT = "10000000-0000-4000-8000-000000000020"


def test_epss_projection_keeps_exact_numbers_and_replay_identity():
    feed = parse_epss_csv(epss(), scope=scope("FIRST"))
    record = next(normalize_public(feed))
    rows = list(record.evidence_rows(RECEIPT))
    assert rows[0][0] == "epss_observations"
    assert rows[0][1]["probability"] == Decimal("0.12345678901234567890123456789")
    assert rows == list(record.evidence_rows(RECEIPT))
    assert (
        rows[0][1]["id"]
        != list(record.evidence_rows("10000000-0000-4000-8000-000000000021"))[0][1][
            "id"
        ]
    )
    assert (
        json.loads(record.claim)["record"]["probability"]["decimal"]
        == "0.12345678901234567890123456789"
    )


def test_kev_does_not_invent_absence_patch_or_due_date_semantics():
    record = next(normalize_public(parse_kev_json(wire(kev()), scope=scope("CISA"))))
    rows = dict(record.evidence_rows(RECEIPT))
    assert set(rows) == {"kev_observations", "vulnerability_details"}
    assert rows["kev_observations"]["membership"] is True
    assert "source_due_date" in rows["kev_observations"]
    assert json.loads(record.claim)["raw"]["futureField"]["unknown"] == [False, None]


def test_nvd_keeps_all_metrics_and_languages_without_inferred_patch_links():
    document = nvd()
    source = document["vulnerabilities"][0]["cve"]
    source["descriptions"].append({"lang": "fr", "value": "Exemple synthétique"})
    source["metrics"]["ssvcV203"] = [{"synthetic": True}]
    record = next(normalize_public(parse_nvd_json(wire(document), scope=scope("NVD"))))
    rows = list(record.evidence_rows(RECEIPT))
    assert sum(table == "cvss_observations" for table, _ in rows) == 4
    assert sum(table == "vulnerability_details" for table, _ in rows) == 2
    assert all(row["cve_id"] == CVE for _, row in rows)
    assert all(
        "published_at" not in row for table, row in rows if table == "cvss_observations"
    )
    assert len({row["id"] for _, row in rows}) == len(rows)
    raw = json.loads(record.claim)["raw"]
    assert raw["descriptions"][1]["lang"] == "fr"
    assert raw["metrics"]["ssvcV203"] == [{"synthetic": True}]
    assert raw["references"][0]["tags"] == ["Vendor Advisory"]
    assert not any("patch" in table for table, _ in rows)


def test_changed_source_fact_changes_hash_but_repeated_feed_does_not():
    feed = parse_epss_csv(epss(), scope=scope("FIRST"))
    first = next(normalize_public(feed))
    assert first == next(normalize_public(feed))
    changed = replace(feed, model_version="synthetic-next")
    assert first.content_hash != next(normalize_public(changed)).content_hash


def test_empty_complete_public_feed_yields_no_invented_records():
    document = kev()
    document.update(count=0, vulnerabilities=[])
    assert (
        list(normalize_public(parse_kev_json(wire(document), scope=scope("CISA"))))
        == []
    )


def test_repeated_reference_url_has_one_projection_and_all_source_claims():
    document = nvd()
    references = document["vulnerabilities"][0]["cve"]["references"]
    references.append({**references[0], "source": "another-synthetic-publisher"})
    record = next(normalize_public(parse_nvd_json(wire(document), scope=scope("NVD"))))
    assert (
        sum(
            table == "vulnerability_references"
            for table, _ in record.evidence_rows(RECEIPT)
        )
        == 1
    )
    assert len(json.loads(record.claim)["raw"]["references"]) == 2
