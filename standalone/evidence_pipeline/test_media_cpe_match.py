"""CPE version exclusion is not an unaffected or patch-applicability assertion."""

from backend.database import schema as database_schema

import json
import sys
import pytest
from .test_store import db as db

from .test_media_inventory_match import facts
from standalone.evidence_pipeline.assessment.media_cpe_match import (
    evaluate_configurations,
)


@pytest.fixture(params=["python", "sql"], autouse=True)
def evaluator_backend(request, monkeypatch):
    if request.param == "python":
        yield
        return
    connection = request.getfixturevalue("db")
    with connection.cursor() as cursor:
        database_schema.verify(cursor)
        cursor.execute("SET LOCAL ROLE tm_mock_reader")

        def call(configurations, facts):
            cursor.execute(
                "SELECT evidence_pipeline.media_cpe_status(%s::jsonb,%s::jsonb)",
                (json.dumps(configurations), json.dumps(facts)),
            )
            actual = cursor.fetchone()[0]
            expected = python_evaluate(configurations, facts)
            assert actual == expected
            return actual

        python_evaluate = evaluate_configurations
        monkeypatch.setattr(sys.modules[__name__], "evaluate_configurations", call)
        yield


def configuration(**changes):
    criterion = (
        dict(
            criteria="cpe:2.3:a:microsoft:av1_video_extension:*:*:*:*:*:*:*:*",
            vulnerable=True,
            versionStartIncluding="1.1.0",
            versionEndExcluding="1.1.60961.0",
        )
        | changes
    )
    return [dict(nodes=[dict(operator="OR", negate=False, cpeMatch=[criterion])])]


@pytest.mark.parametrize(
    "version,state",
    [("1.1.50000.0", "matched"), ("2.0.30.0", "excluded"), ("1.1.0.0", "unknown")],
)
def test_independent_version_condition(version, state):
    f = facts()
    f["version"] = f["manifest"]["version"] = version
    assert evaluate_configurations(configuration(), f)["state"] == state


@pytest.mark.parametrize(
    "change",
    [
        {"is_bundle": True},
        {"publisher": "Other"},
        {"operating_system": "Unknown"},
        {"manifest": None},
        {"user_states": []},
        {"product": "Microsoft.HEVCVideoExtension"},
    ],
)
def test_unestablished_identity_never_evaluates(change):
    assert (
        evaluate_configurations(configuration(), facts() | change)["state"] == "unknown"
    )


@pytest.mark.parametrize(
    "change",
    [
        {"criteria": "cpe:2.3:a:microsoft:hevc_video_extensions:*:*:*:*:*:*:*:*"},
        {"criteria": "cpe:2.3:a:microsoft:av1_video_extension:*:*:special:*:*:*:*:*"},
        {"versionStartIncluding": "2.0", "versionEndExcluding": "1.0"},
        {"versionEndIncluding": "1.2.3.4"},
        {"unsupported": True},
    ],
)
def test_unknown_or_conflicting_selector(change):
    assert (
        evaluate_configurations(configuration(**change), facts())["state"] == "unknown"
    )


def test_environment_and_condition_cannot_be_silently_ignored():
    conf = configuration()
    conf[0]["nodes"][0]["operator"] = "AND"
    conf[0]["nodes"][0]["cpeMatch"].append(
        dict(criteria="cpe:2.3:o:unknown:os:*:*:*:*:*:*:*:*", vulnerable=False)
    )
    assert evaluate_configurations(conf, facts())["state"] == "unknown"
