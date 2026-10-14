"""SQL/Python parity and authority checks for supported Store media conditions."""

from backend.database import schema as database_schema

import json
from copy import deepcopy
import pytest
from .test_store import db as db


from standalone.evidence_pipeline.assessment.media_inventory_match import (
    MEDIA_PRODUCTS,
    evaluate_media,
)
from standalone.evidence_pipeline.assessment.media_cpe_match import (
    evaluate_configurations,
)
from .test_media_inventory_match import facts, source


@pytest.fixture
def sql(db):
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute("SET LOCAL ROLE tm_mock_reader")

        def call(s, f):
            cur.execute(
                "SELECT evidence_pipeline.media_inventory_status(%s::jsonb,%s,%s::jsonb),evidence_pipeline.media_cpe_status(%s::jsonb,%s::jsonb)",
                (
                    json.dumps(s),
                    "microsoft",
                    json.dumps(f),
                    json.dumps(s.get("cpeApplicability")),
                    json.dumps(f),
                ),
            )
            return cur.fetchone()

        yield call


@pytest.mark.parametrize("product", MEDIA_PRODUCTS)
@pytest.mark.parametrize(
    "case",
    [
        "matching",
        "upper_boundary",
        "bundle",
        "wrong_family",
        "wrong_publisher",
        "wrong_manifest",
        "unknown_platform",
        "conflicting_rule",
    ],
)
def test_sql_matches_python_for_every_supported_product(sql, product, case):
    f = facts()
    name, cpe = MEDIA_PRODUCTS[product]
    f.update(product=product, name=product, family_name=product + "_8wekyb3d8bbwe")
    f["manifest"].update(name=product, display_name=name)
    s = source()
    entry = s["affected"][0]
    entry.update(product=name)
    entry["versions"][0]["version"] = "1.1.0.0"
    s["cpeApplicability"] = [
        {
            "nodes": [
                {
                    "operator": "OR",
                    "negate": False,
                    "cpeMatch": [
                        {
                            "vulnerable": True,
                            "criteria": f"cpe:2.3:a:microsoft:{cpe}:*:*:*:*:*:*:*:*",
                            "versionStartIncluding": "1.1.0.0",
                            "versionEndExcluding": "1.1.60961.0",
                        }
                    ],
                }
            ]
        }
    ]
    if case == "upper_boundary":
        f["version"] = f["manifest"]["version"] = "1.1.60961.0"
    elif case == "bundle":
        f["is_bundle"] = True
    elif case == "wrong_family":
        f["family_name"] = "Synthetic.Other"
    elif case == "wrong_publisher":
        f["publisher"] = "Synthetic publisher"
    elif case == "wrong_manifest":
        f["manifest"]["display_name"] = "Synthetic similar name"
    elif case == "unknown_platform":
        entry["platforms"] = ["Unknown"]
    elif case == "conflicting_rule":
        entry["versions"].append(entry["versions"][0] | {"status": "unaffected"})
    expected = evaluate_media(s, provider="microsoft", facts=f)
    cpe_expected = evaluate_configurations(s["cpeApplicability"], f)
    before = deepcopy((s, f))
    actual, cpe_actual = sql(s, f)
    assert {k: actual[k] for k in expected} == expected
    assert cpe_actual == cpe_expected
    assert actual["applicability"] == "unknown" and (s, f) == before


def test_codec_upgrade_checks_schema_authority_drift(db, sql):
    with db.cursor() as cur:
        cur.execute("RESET ROLE")
        cur.execute(
            "GRANT EXECUTE ON FUNCTION evidence_pipeline.media_inventory_status(jsonb,text,jsonb) TO PUBLIC"
        )
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cur)


def test_codec_sql_artifact_is_part_of_migration_identity(db, sql):
    with db.cursor() as cur:
        cur.execute("RESET ROLE")
        cur.execute(
            "UPDATE evidence_pipeline.installation SET artifacts=artifacts-'schema.sql' WHERE singleton"
        )
        with pytest.raises(ValueError, match="metadata differs"):
            database_schema.verify(cur)
