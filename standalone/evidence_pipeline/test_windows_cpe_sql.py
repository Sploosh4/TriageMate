"""Restricted SQL conditions agree with the reference and retain authority."""

from backend.database import schema as database_schema

from copy import deepcopy
import json
import pytest
from .test_store import db as database_fixture
from .test_windows_cpe_match import criterion, configuration
from .test_windows_version_match import FACTS
from .test_windows_cna_match import entry
from standalone.evidence_pipeline.assessment.windows_cpe_match import (
    evaluate_configurations,
)
from standalone.evidence_pipeline.assessment.windows_cna_match import evaluate_record


db = database_fixture


def condition_cases():
    for left in ("matched", "excluded", "unknown"):
        for right in ("matched", "excluded", "unknown"):
            for operator in ("AND", "OR"):
                for negate in (False, True):
                    yield configuration(
                        criterion(left),
                        criterion(right),
                        operator=operator,
                        negate=negate,
                    )
    for state in ("matched", "excluded", "unknown"):
        for vulnerable in (False, True):
            yield configuration(criterion(state, vulnerable))
    double = configuration(criterion(), negate=True)
    double[0]["negate"] = True
    yield double
    yield [
        {
            "operator": "AND",
            "nodes": [
                {"operator": "OR", "cpeMatch": [criterion()]},
                {
                    "operator": "OR",
                    "negate": True,
                    "cpeMatch": [criterion("excluded", False)],
                },
            ],
        }
    ]
    for value in (
        None,
        {},
        [],
        [None],
        [{"nodes": []}],
        [{"nodes": [None]}],
        [{"nodes": [{"cpeMatch": [criterion()]}]}],
    ):
        yield value
    for product in ("windows_11_24h2", "windows_server_2025", "windows_server_unknown"):
        for vulnerable in (False, True):
            yield configuration(
                {
                    "criteria": criterion()["criteria"].replace(
                        "windows_11_25h2", product
                    ),
                    "vulnerable": vulnerable,
                }
            )
    for extra in ({"operator": "XOR"}, {"negate": "false"}, {"unexpected": True}):
        value = configuration(criterion())
        value[0].update(extra)
        yield value
    for bounds in (
        {"versionEndIncluding": "10.0.26200.100"},
        {"versionEndExcluding": "10.0.26200.100"},
        {"versionStartIncluding": "10.0.26200.100"},
        {"versionStartExcluding": "10.0.26200.100"},
        {
            "versionStartIncluding": "10.0.26200.200",
            "versionEndIncluding": "10.0.26200.100",
        },
        {"versionStartIncluding": "bad"},
        {
            "versionStartIncluding": "10.0.26200.1",
            "versionStartExcluding": "10.0.26200.2",
        },
        {"criteria": criterion()["criteria"].replace(":*:", ":10.0.26200.100:", 1)},
        {"criteria": "cpe:2.3:a:example:missing:*:*:*:*:*:*:*:*"},
        {"criteria": "invalid"},
        {"vulnerable": "true"},
    ):
        yield configuration({**criterion(), **bounds})


def test_reader_cpe_and_full_record_parity(db):
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        for index, conditions in enumerate(condition_cases()):
            cur.execute(
                "SELECT evidence_pipeline.windows_cpe_status(%s::jsonb,%s::jsonb)",
                (json.dumps(conditions), json.dumps(FACTS)),
            )
            assert cur.fetchone()[0] == evaluate_configurations(
                conditions, facts=FACTS
            ), index
            for state in ("affected", "unaffected", "unknown"):
                product = entry()
                product["versions"][0]["status"] = state
                record = dict(affected=[product], cpeApplicability=conditions)
                cur.execute(
                    "SELECT evidence_pipeline.windows_cna_record_status(%s::jsonb,%s,%s::jsonb)",
                    (json.dumps(record), "Microsoft", json.dumps(FACTS)),
                )
                assert cur.fetchone()[0] == evaluate_record(
                    record, provider="Microsoft", facts=FACTS
                ), (index, state)
        for facts in (
            {},
            None,
            {**FACTS, "os_processor": None},
            {**FACTS, "release": "ambiguous"},
        ):
            conditions = configuration(criterion())
            cur.execute(
                "SELECT evidence_pipeline.windows_cpe_status(%s::jsonb,%s::jsonb)",
                (json.dumps(conditions), json.dumps(facts)),
            )
            assert cur.fetchone()[0] == evaluate_configurations(
                deepcopy(conditions), facts=facts
            )


@pytest.mark.parametrize(
    "damage",
    [
        "ALTER FUNCTION evidence_pipeline.windows_cna_record_status(jsonb,text,jsonb) SECURITY DEFINER",
        "GRANT EXECUTE ON FUNCTION evidence_pipeline.windows_cpe_criterion(jsonb,jsonb) TO PUBLIC",
        "REVOKE EXECUTE ON FUNCTION evidence_pipeline.windows_cpe_status(jsonb,jsonb) FROM tm_mock_reader",
    ],
)
def test_cpe_function_authority_drift_rejected(db, damage):
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute(damage)
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cur)
