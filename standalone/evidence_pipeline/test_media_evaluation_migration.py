"""Restricted SQL matches the independently tested conservative evaluator."""

from backend.database import schema as database_schema

import json
from copy import deepcopy
import pytest

from .test_store import db as db
from .test_media_inventory_match import facts, source
from standalone.evidence_pipeline.assessment.media_inventory_match import evaluate_media


@pytest.fixture
def sql(db):
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute("SET LOCAL ROLE tm_mock_reader")

        def call(s, f, provider="microsoft"):
            cur.execute(
                "SELECT evidence_pipeline.media_inventory_status(%s::jsonb,%s,%s::jsonb)",
                (json.dumps(s), provider, json.dumps(f)),
            )
            return cur.fetchone()[0]

        yield call


def compare(sql, s, f, provider="microsoft"):
    actual = sql(s, f, provider)
    expected = evaluate_media(s, provider=provider, facts=f)
    for key in expected:
        assert actual[key] == expected[key], (key, actual, expected)
    return actual


@pytest.mark.parametrize(
    "change",
    [
        {},
        {"source": "Intune"},
        {"product": "Microsoft.HEVCVideoExtension"},
        {"name": "Other"},
        {"publisher": "Microsoft Corporation"},
        {"family_name": "other"},
        {"kind": "registry"},
        {"is_bundle": True},
        {"is_framework": True},
        {"is_resource_package": True},
        {"is_bundle": None},
        {"native_id": ""},
        {"user_states": None},
        {"user_states": []},
        {"user_states": [{"install_state": "Staged"}]},
        {"manifest": None},
        {"operating_system": "unknown"},
        {"platform": "linux"},
    ],
)
def test_inventory_boundaries_agree(sql, change):
    compare(sql, source(), facts() | change)


@pytest.mark.parametrize(
    "change",
    [
        {"name": "Other"},
        {"version": "1.2.3.4"},
        {"sha256": None},
        {"display_name": "AV1 Video Extensions"},
        {"display_name": None},
        {"resource_lookup_hresult": -1},
        {"resource_lookup_hresult": True},
        {"resource_lookup_hresult": 2147483648},
        {"unexpected": "field"},
        {"resolution_culture": None},
        {"display_name_reference": "ms-resource:../Name"},
    ],
)
def test_manifest_boundaries_agree(sql, change):
    f = facts()
    f["manifest"].update(change)
    compare(sql, source(), f)


@pytest.mark.parametrize("selector", ["platforms", "modules", "cpes"])
def test_conditions_agree(sql, selector):
    s = source()
    s["affected"][0][selector] = ["Unknown"]
    compare(sql, s, facts())


@pytest.mark.parametrize("selector", ["configurations", "cpeApplicability"])
def test_top_level_conditions_agree(sql, selector):
    compare(sql, source() | {selector: []}, facts())


@pytest.mark.parametrize(
    "version", ["1.1.0.0", "1.1.50000.0", "1.1.60961.0", "2.0.0.0", "bad"]
)
@pytest.mark.parametrize("default", [None, "unaffected", "affected"])
def test_bounds_and_absent_defaults_agree(sql, version, default):
    s = source()
    f = facts()
    f["version"] = f["manifest"]["version"] = version
    if default is not None:
        s["affected"][0]["defaultStatus"] = default
    compare(sql, s, f)


def test_conflicting_rules_and_entries_agree(sql):
    s = source()
    s["affected"][0]["versions"].append(
        dict(version="1.1.50000.0", status="unaffected")
    )
    compare(sql, s, facts())
    s = source()
    s["affected"].append(deepcopy(s["affected"][0]))
    s["affected"][1]["versions"][0]["status"] = "unaffected"
    compare(sql, s, facts())


@pytest.mark.parametrize("provider", ["other", None, "Microsoft"])
def test_provider_boundary_agrees(sql, provider):
    compare(sql, source(), facts(), provider)
