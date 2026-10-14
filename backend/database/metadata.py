"""Current installation annotations and the frozen adoption annotation contract."""

import hashlib
import json
from pathlib import Path

from .baseline.profiles import PROFILES

BASE = Path(__file__).with_name("baseline")
BOOTSTRAP = "triagemate-baseline-v1"
PRE_METADATA_TOOL_HASH = (
    "5fa79fa1c97db2e1bd323630e2e5337f4c391e40522a48e71b5355f34f56585a"
)


def annotation(profile: str) -> dict[str, object]:
    if profile not in PROFILES:
        raise ValueError("Unknown database installation profile")
    return {
        "bootstrap": BOOTSTRAP,
        "profile": profile,
        "synthetic": profile != "empty",
        "fixture_sha256": hashlib.sha256(
            (BASE / "fixtures.json").read_bytes()
        ).hexdigest()
        if profile != "empty"
        else None,
    }


def original_tables() -> list[tuple[str, str]]:
    value = json.loads((BASE / "original-tables.json").read_text())
    return [(str(schema), str(table)) for schema, table in value]


def legacy_annotation_matches(profile: str, value: object) -> bool:
    if profile not in PROFILES or not isinstance(value, dict):
        return False
    legacy = json.loads((BASE / "legacy-annotations.json").read_text())
    expected = legacy["annotations"][profile]
    if value == expected:
        return True
    if profile == "empty":
        return False
    # These exact manage.py hashes were accepted by the predecessor's manifest
    # verifier. No arbitrary source edits or unrecognized schema hashes qualify.
    for digest in legacy["accepted_manage_hashes"]:
        candidate = {**expected, "sha256": {**expected["sha256"], "manage.py": digest}}
        # Exact predecessor manage.py matches_manifest case at d34acea2:
        # this tool predates catalogue annotations, not the catalogue itself.
        if digest == PRE_METADATA_TOOL_HASH:
            candidate["sha256"].pop("catalogue_metadata.sql")
        if value == candidate:
            return True
    return False
