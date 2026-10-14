"""Preserve exact predecessor annotation variants without relaxing source hashes."""

from copy import deepcopy
import json

import pytest

from backend.database.metadata import BASE, legacy_annotation_matches

PRE_METADATA = "5fa79fa1c97db2e1bd323630e2e5337f4c391e40522a48e71b5355f34f56585a"
OTHER_TOOLS = [
    "075b8a46c5e4db58209dbc41aac85c946705f2a4b3f7d6b6d9784d68f909591c",
    "2423f1870c107798b249f21046f7fe63b7264e714f737085bf61ce80a4a0c02e",
]


@pytest.fixture(params=["synthetic", "runner"])
def reference(request):
    document = json.loads((BASE / "legacy-annotations.json").read_text())
    return request.param, deepcopy(document["annotations"][request.param])


@pytest.mark.parametrize("tool", [None, PRE_METADATA, *OTHER_TOOLS])
def test_exact_historical_tool_annotation_shapes(reference, tool):
    profile, value = reference
    if tool is not None:
        value["sha256"]["manage.py"] = tool
    if tool == PRE_METADATA:
        value["sha256"].pop("catalogue_metadata.sql")
    assert legacy_annotation_matches(profile, value)


@pytest.mark.parametrize(
    "damage",
    ["catalogue_present", "wrong_tool", "schema", "fixtures", "extra", "missing"],
)
def test_old_annotation_does_not_allow_other_hash_or_shape_changes(reference, damage):
    profile, value = reference
    value["sha256"]["manage.py"] = PRE_METADATA
    if damage != "catalogue_present":
        value["sha256"].pop("catalogue_metadata.sql")
    if damage == "wrong_tool":
        value["sha256"]["manage.py"] = OTHER_TOOLS[0]
    elif damage in {"schema", "fixtures"}:
        value["sha256"][damage + (".sql" if damage == "schema" else ".json")] = "0" * 64
    elif damage == "extra":
        value["unrecognized"] = True
    elif damage == "missing":
        value.pop("epss_functions_sha256")
    assert not legacy_annotation_matches(profile, value)


def test_empty_profile_does_not_accept_synthetic_legacy_variants():
    document = json.loads((BASE / "legacy-annotations.json").read_text())
    assert legacy_annotation_matches("empty", document["annotations"]["empty"])
    assert not legacy_annotation_matches("empty", document["annotations"]["synthetic"])
