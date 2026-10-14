"""Generated CSAF fixtures retain Red Hat package/platform relationships."""

from dataclasses import replace
import json
from uuid import uuid4
import pytest

from .contracts import SourceScope
from standalone.evidence_pipeline.parsing.redhat_advisories import parse_redhat
from standalone.evidence_pipeline.parsing.redhat_discovery import BASE
from .test_csaf import fixture


def scope():
    return SourceScope(
        str(uuid4()),
        "Red Hat",
        "advisories",
        BASE + "2099/rhsa-2099_1234.json",
        "synthetic",
        "TriageMate generated synthetic Red Hat fixture",
    )


def document():
    raw = fixture()
    raw["document"]["tracking"]["id"] = "RHSA-2099:1234"
    raw["document"]["publisher"]["name"] = "Synthetic Red Hat fixture"
    product = raw["product_tree"]["branches"][0]["product"]
    product["name"] = "Synthetic RPM package"
    product["product_identification_helper"] = {
        "purl": "pkg:rpm/redhat/synthetic@1.2?arch=src&epoch=1",
        "cpe": "cpe:/a:synthetic:package:1",
        "future_extension": {"retained": True},
    }
    raw["product_tree"]["relationships"] = [
        {
            "category": "default_component_of",
            "product_reference": "p1",
            "relates_to_product_reference": "p1",
            "full_product_name": {
                "product_id": "combined",
                "name": "Synthetic combined product",
            },
        }
    ]
    return raw


def test_source_document_helpers_and_relationships_are_preserved():
    raw = document()
    feed = parse_redhat(json.dumps(raw).encode(), scope=scope())
    assert feed.source_document == raw
    assert feed.product_definitions[0]["product_identification_helper"][
        "future_extension"
    ] == {"retained": True}
    assert feed.product_relationships == tuple(raw["product_tree"]["relationships"])
    assert feed.records[0].remediations[0].patch_id is None


@pytest.mark.parametrize(
    "damage", ["identity", "endpoint", "helper", "duplicate", "path", "tenant"]
)
def test_invalid_identity_and_relationships_rejected(damage):
    raw = document()
    chosen = scope()
    if damage == "identity":
        raw["document"]["tracking"]["id"] = "RHSA-2099:9999"
    elif damage == "endpoint":
        raw["product_tree"]["relationships"][0]["product_reference"] = "missing"
    elif damage == "helper":
        raw["product_tree"]["branches"][0]["product"]["product_identification_helper"][
            "purl"
        ] = []
    elif damage == "duplicate":
        raw["product_tree"]["relationships"][0]["full_product_name"]["product_id"] = (
            "p1"
        )
    elif damage == "path":
        chosen = replace(chosen, scope_reference=chosen.scope_reference + "?x=1")
    else:
        chosen = replace(chosen, tenant_id=str(uuid4()))
    with pytest.raises(ValueError):
        parse_redhat(json.dumps(raw).encode(), scope=chosen)


def test_reference_reconstruction_detects_tree_projection_tampering():
    from standalone.evidence_pipeline.parsing.reference_records import (
        normalize_references,
    )
    from standalone.evidence_pipeline.persistence.reference_attribution import (
        reconstruct_reference,
    )
    from standalone.evidence_pipeline.parsing.public_records import canonical
    from standalone.evidence_pipeline.parsing.cve_records import source_json

    chosen = scope()
    record = next(
        normalize_references(
            parse_redhat(json.dumps(document()).encode(), scope=chosen)
        )
    )
    assert reconstruct_reference(chosen, record.claim) == record
    claim = json.loads(record.claim)
    fields = json.loads(claim["source_fields"])
    fields["products"][0]["name"] = "Altered product"
    claim["source_fields"] = source_json(fields)
    with pytest.raises(ValueError, match="disagrees"):
        reconstruct_reference(chosen, canonical(claim))
