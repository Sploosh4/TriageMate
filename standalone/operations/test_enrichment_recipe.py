"""Synthetic enrichment fixtures cannot expand into unrelated/private requests."""

import json
from uuid import uuid4

import pytest

from standalone.evidence_pipeline.contracts import SourceScope
from .enrichment_recipe import EnrichmentRecipe


@pytest.mark.parametrize(
    "damage", [None, "origin", "identity", "payload", "duplicate", "permissions"]
)
def test_exact_fixture_boundary(tmp_path, damage):
    request = str(uuid4())
    scope = SourceScope(
        str(uuid4()),
        "NVD",
        "enrichment_queue",
        "triagemate:enrichment/NVD",
        "synthetic",
        "Explicitly synthetic fixture acceptance",
    )
    document = dict(origin="synthetic", requests={request: '{ "synthetic": true }\n'})
    if damage == "origin":
        document["origin"] = "public"
    elif damage == "identity":
        document["requests"] = {"not-an-id": "{}"}
    elif damage == "payload":
        document["requests"][request] = {}
    wire = json.dumps(document)
    if damage == "duplicate":
        wire = wire.replace(
            '"origin": "synthetic"', '"origin": "synthetic", "origin": "synthetic"'
        )
    path = tmp_path / "synthetic.json"
    path.write_text(wire)
    path.chmod(0o644 if damage == "permissions" else 0o600)
    recipe = EnrichmentRecipe(scope, tmp_path, path)
    if damage:
        with pytest.raises(ValueError):
            recipe.fixtures()
    else:
        assert recipe.fixtures() == {request: b'{ "synthetic": true }\n'}
