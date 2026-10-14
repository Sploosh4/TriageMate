"""Synthetic Tools version rules agree through the restricted SQL role."""

from backend.database import schema as database_schema

from copy import deepcopy
import json

from .test_store import db as database_fixture
from .test_vmware_tools_match import ENTRY
from standalone.evidence_pipeline.assessment.vmware_tools_match import (
    _version_match,
    version_key,
)


db = database_fixture


def test_restricted_version_rule_parity(db):
    rules = [deepcopy(ENTRY["versions"][0])]
    for change in (
        {"version": "13.0.1"},
        {"version": "13.x.1"},
        {"version": "x.x.x"},
        {"version": "13.0.0", "lessThan": "12.0.0"},
        {"version": "13.x.x", "lessThanOrEqual": "13.0.5"},
        {"status": []},
        {"versionType": {}},
        {"versionType": None},
        {"changes": []},
        {"lessThan": None},
        {"lessThan": "13.0.01"},
    ):
        rules.append({**rules[0], **change})
    rules.extend(
        [
            dict(version="13.x.x", status="affected"),
            dict(version="13.0.1", status="unaffected"),
            dict(version="13.0.0", lessThanOrEqual="13.0.5", status="affected"),
            None,
            [],
            {},
        ]
    )
    with db.cursor() as cur:
        # Verify an existing install or apply transactionally on its predecessor.
        database_schema.verify(cur)
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        for version in ("12.9.9", "13.0.0", "13.0.1", "13.0.1.1", "13.0.5", "14.0.0"):
            candidate = version_key(version)
            cur.execute("SELECT evidence_pipeline.vmware_tools_version(%s)", (version,))
            assert tuple(cur.fetchone()[0]) == candidate
            for rule in rules:
                cur.execute(
                    "SELECT evidence_pipeline.vmware_tools_version_match(%s::jsonb,%s::bigint[])",
                    (json.dumps(rule), list(candidate)),
                )
                assert cur.fetchone()[0] == _version_match(rule, candidate), (
                    rule,
                    version,
                )
        for value in (None, "13.0", "13.0.01", "13.0.1-beta", "13.0.1.0.0"):
            cur.execute("SELECT evidence_pipeline.vmware_tools_version(%s)", (value,))
            assert cur.fetchone()[0] is None


def test_restricted_product_statement_parity(db):
    from .test_vmware_tools_match import FACTS
    from standalone.evidence_pipeline.assessment.vmware_tools_match import (
        evaluate_tools,
    )

    cases = [([deepcopy(ENTRY)], dict(FACTS))]
    for field in ("defaultStatus", "versions", "platforms", "vendor", "product"):
        for value in (None, [], {}, "unsupported"):
            cases.append(([{**deepcopy(ENTRY), field: value}], dict(FACTS)))
    for field in ("status", "versionType", "version", "lessThan"):
        for value in (None, [], {}, "unsupported"):
            entry = deepcopy(ENTRY)
            entry["versions"][0][field] = value
            cases.append(([entry], dict(FACTS)))
    for field in ("provider", "product", "publisher", "version", "operating_system"):
        for value in (None, [], {}, "unsupported"):
            cases.append(([deepcopy(ENTRY)], {**FACTS, field: value}))
    for version in ("13.0.5", "13.0.5.1", "12.0.1", "14.0.0"):
        cases.append(([deepcopy(ENTRY)], {**FACTS, "version": version}))
    other = deepcopy(ENTRY)
    other["versions"][0]["status"] = "unaffected"
    cases.append(([deepcopy(ENTRY), other], dict(FACTS)))
    cases.append(([other, deepcopy(ENTRY)], dict(FACTS)))
    combined = deepcopy(ENTRY)
    combined["versions"].append(other["versions"][0])
    cases.append(([deepcopy(combined)], dict(FACTS)))
    combined["versions"].append({"version": "unsupported", "status": "affected"})
    cases.append(([combined], dict(FACTS)))
    for value in (None, [], {}, [None], [[], ENTRY]):
        cases.append((value, dict(FACTS)))
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        for index, (entries, facts) in enumerate(cases):
            expected = evaluate_tools(entries, **facts)
            provider = facts["provider"]
            # Provider is a SQL text argument; malformed JSON identity remains an
            # unsupported string rather than being silently coerced into a match.
            if provider is not None and not isinstance(provider, str):
                provider = json.dumps(provider)
            cur.execute(
                "SELECT evidence_pipeline.vmware_tools_status(%s::jsonb,%s,%s::jsonb)",
                (json.dumps(entries), provider, json.dumps(facts)),
            )
            assert cur.fetchone()[0] == expected, index


def test_additive_migration_restricted_view_and_idempotence(db):

    with db.cursor() as cur:
        cur.execute(
            "SELECT version, artifacts ? 'schema.sql' FROM evidence_pipeline.installation WHERE singleton"
        )
        previous, already_installed = cur.fetchone()
        assert already_installed, (
            "The consolidated baseline artifact must be registered"
        )
        database_schema.verify(cur)
        if already_installed:
            cur.execute(
                "SELECT version FROM evidence_pipeline.installation WHERE singleton"
            )
            assert cur.fetchone() == (previous,)
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        cur.execute(
            "SELECT finding_receipt_id,device_attempt_id,device_receipt_id,"
            "public_receipt_id,tenant_id,device_origin,public_origin,pinned_facts,"
            "source_fields,source_product_version_status,interpretation "
            "FROM evidence_pipeline.current_vmware_tools_cna_evaluations LIMIT 0"
        )
        assert len(cur.description) == 11


def test_migration_rejects_evaluator_authority_drift(db):

    import pytest

    with db.cursor() as cur:
        database_schema.verify(cur)
        for damage in (
            "ALTER FUNCTION evidence_pipeline.vmware_tools_status(jsonb,text,jsonb) SECURITY DEFINER",
            "GRANT EXECUTE ON FUNCTION evidence_pipeline.vmware_tools_status(jsonb,text,jsonb) TO PUBLIC",
            "REVOKE EXECUTE ON FUNCTION pg_catalog.cardinality(anyarray) FROM tm_mock_reader",
            "REVOKE SELECT ON evidence_pipeline.current_vmware_tools_cna_evaluations FROM tm_mock_reader",
        ):
            cur.execute("SAVEPOINT authority_check")
            cur.execute(damage)
            with pytest.raises(ValueError, match="schema/authority differs"):
                database_schema.verify(cur)
            cur.execute("ROLLBACK TO SAVEPOINT authority_check")


def test_existing_entry_points_verify_additive_upgrade(db):

    from standalone.evidence_pipeline.persistence.store import require_input_migration
    from .test_exposure_migration import (
        test_original_schema_verifier_accepts_only_recognized_upgrade as original_check,
    )

    with db.cursor() as cur:
        database_schema.verify(cur)
        for feature in ("update-status", "antivirus", "catalogue"):
            require_input_migration(cur, feature)
        database_schema.verify(cur)
    original_check(db)
