"""Synthetic repository fixtures preserve exact bytes and reject ambiguous inputs."""

import json

import pytest

from .repository_recipe import fixtures


@pytest.mark.parametrize(
    "damage", [None, "origin", "duplicate", "payload", "duplicate_key", "permissions"]
)
def test_fixture_boundary(tmp_path, damage):
    wire = '{ "explicitly_synthetic": true }\n'
    item = dict(kind="trees", identity="a" * 40, payload=wire)
    document = dict(
        origin="synthetic", objects=[item], records={"synthetic.json": wire}
    )
    if damage == "origin":
        document["origin"] = "public"
    elif damage == "duplicate":
        document["objects"].append(item)
    elif damage == "payload":
        document["records"]["synthetic.json"] = {}
    payload = json.dumps(document)
    if damage == "duplicate_key":
        payload = payload.replace(
            '"origin": "synthetic"', '"origin": "synthetic", "origin": "synthetic"'
        )
    path = tmp_path / "synthetic.json"
    path.write_text(payload)
    path.chmod(0o644 if damage == "permissions" else 0o600)
    if damage:
        with pytest.raises(ValueError):
            fixtures(path)
    else:
        objects, records = fixtures(path)
        assert objects == {("trees", "a" * 40): wire.encode()}
        assert records == {"synthetic.json": wire.encode()}
