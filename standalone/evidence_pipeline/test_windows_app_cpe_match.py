"""Synthetic Teams conditions agree with the installed restricted SQL functions."""

from backend.database import schema as database_schema

from copy import deepcopy
import json

import pytest

from .test_store import db as db
from standalone.evidence_pipeline.assessment.windows_app_match import (
    PACKAGE_PUBLISHER,
    evaluate_windows_app,
)
from standalone.evidence_pipeline.assessment.windows_app_cpe_match import (
    evaluate_criterion,
    evaluate_configurations,
)

FACTS = dict(
    source="Intune",
    product="MSTeams",
    publisher=PACKAGE_PUBLISHER,
    platform="windows",
    operating_system="Windows11",
    version="2.0.0.0",
)
CPE = "cpe:2.3:a:microsoft:teams:*:*:*:*:*:*:*:*"


def criterion(**extra):
    return dict(criteria=CPE, vulnerable=True) | extra


def configuration(*criteria, operator="OR", negate=False):
    return [
        dict(nodes=[dict(operator=operator, negate=negate, cpeMatch=list(criteria))])
    ]


@pytest.fixture(params=["python", "sql"])
def evaluators(request):
    if request.param == "python":
        return evaluate_criterion, evaluate_configurations, evaluate_windows_app
    connection = request.getfixturevalue("db")
    with connection.cursor() as cursor:
        database_schema.verify(cursor)
        cursor.execute("SET LOCAL ROLE tm_mock_reader")

    def call(name, *values):
        with connection.cursor() as cursor:
            casts = (
                "%s::jsonb,%s::text,%s::jsonb"
                if len(values) == 3
                else "%s::jsonb,%s::jsonb"
            )
            cursor.execute(
                "SELECT evidence_pipeline.windows_app_" + name + "(" + casts + ")",
                tuple(
                    v if i == 1 and len(values) == 3 else json.dumps(v)
                    for i, v in enumerate(values)
                ),
            )
            return cursor.fetchone()[0]

    return (
        lambda item, facts: call("cpe_criterion", item, facts),
        lambda items, facts: call("cpe_status", items, facts),
        lambda source, *, provider, facts: call(
            "inventory_status", source, provider, facts
        ),
    )


@pytest.mark.parametrize(
    "extra,state",
    [
        ({}, "matched"),
        ({"versionStartIncluding": "2.0.0.0"}, "matched"),
        ({"versionStartExcluding": "2.0.0.0"}, "excluded"),
        ({"versionEndIncluding": "2.0.0.0"}, "matched"),
        ({"versionEndExcluding": "2.0.0.0"}, "excluded"),
        (
            {"versionStartIncluding": "1.0.0", "versionEndExcluding": "3.0.0.0"},
            "matched",
        ),
        ({"versionStartIncluding": "2.0.0"}, "unknown"),
        (
            {"versionStartIncluding": "3.0.0.0", "versionEndIncluding": "1.0.0.0"},
            "unknown",
        ),
        (
            {"versionStartIncluding": "2.0.0.0", "versionEndExcluding": "2.0.0.0"},
            "unknown",
        ),
        (
            {"versionStartIncluding": "1.0.0", "versionStartExcluding": "1.0.0"},
            "unknown",
        ),
        ({"versionEndIncluding": "1449/1.0.0"}, "unknown"),
        ({"versionEndIncluding": 2.0}, "unknown"),
        ({"criteria": CPE.replace(":*:", ":2.0.0.0:", 1)}, "matched"),
        ({"criteria": CPE.replace(":*:", ":2.0.0:", 1)}, "unknown"),
        ({"criteria": CPE.replace("teams", "onedrive")}, "unknown"),
        ({"criteria": "cpe:2.3:a:microsoft:teams:*:*:*:*:*:android:*:*"}, "excluded"),
        ({"criteria": "cpe:2.3:a:microsoft:teams:*:*:*:*:*:iphone_os:*:*"}, "excluded"),
        ({"criteria": "cpe:2.3:a:microsoft:teams:*:*:*:*:*:windows:*:*"}, "matched"),
        ({"criteria": "cpe:2.3:a:microsoft:teams:*:*:*:*:new:*:*:*"}, "unknown"),
        ({"criteria": "cpe:2.3:a:microsoft:teams:*:*:*:*:*:*:x64:*"}, "unknown"),
        ({"vulnerable": 1}, "unknown"),
    ],
)
def test_criteria(extra, state, evaluators):
    item = criterion(**extra)
    result = evaluators[0](item, FACTS)
    assert result["state"] == state
    assert result == evaluate_criterion(item, FACTS)


@pytest.mark.parametrize(
    "operator,negate,vulnerable,state",
    [
        ("AND", False, True, "unknown"),
        ("OR", False, True, "matched"),
        ("OR", False, False, "unknown"),
        ("AND", True, True, "unknown"),
    ],
)
def test_boolean_conditions(operator, negate, vulnerable, state, evaluators):
    items = configuration(
        criterion(vulnerable=vulnerable),
        criterion(criteria=CPE.replace("teams", "unobserved")),
        operator=operator,
        negate=negate,
    )
    result = evaluators[1](items, FACTS)
    assert result["state"] == state
    assert result == evaluate_configurations(items, FACTS)


@pytest.mark.parametrize(
    "status,bound,state",
    [
        ("affected", "3.0.0.0", "affected"),
        ("affected", "2.0.0.0", "unknown"),
        ("unaffected", "2.0.0.0", "unaffected"),
        ("unaffected", "3.0.0.0", "unknown"),
        ("unknown", "3.0.0.0", "unknown"),
    ],
)
def test_product_and_cpe_agreement(status, bound, state, evaluators):
    source = dict(
        affected=[
            dict(
                vendor="Microsoft",
                product="Microsoft Teams for Desktop",
                versions=[dict(version="2.0.0.0", status=status)],
            )
        ],
        cpeApplicability=configuration(criterion(versionEndExcluding=bound)),
    )
    before = deepcopy(source)
    result = evaluators[2](source, provider="microsoft", facts=FACTS)
    assert result["state"] == state
    assert result == evaluate_windows_app(source, provider="microsoft", facts=FACTS)
    assert source == before


def test_cpe_migration_idempotence_and_authority(db):

    with db.cursor() as cursor:
        database_schema.verify(cursor)
        cursor.execute(
            "GRANT EXECUTE ON FUNCTION evidence_pipeline.windows_app_cpe_criterion(jsonb,jsonb) TO PUBLIC"
        )
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cursor)
