"""Red Hat CSAF facts with native product identification and relationship context.

The complete document remains source evidence. A product status of fixed is not
proof that the corresponding package is installed on any observed computer.
"""

from dataclasses import dataclass, fields

from standalone.evidence_pipeline.contracts import SourceScope
from standalone.evidence_pipeline.parsing.csaf import CsafFeed, parse_csaf
from standalone.evidence_pipeline.parsing.public_inputs import (
    _json,
    _object,
    _array,
    _text,
)
from standalone.evidence_pipeline.parsing.redhat_discovery import BASE, advisory_file


@dataclass(frozen=True)
class RedHatFeed(CsafFeed):
    source_document: dict
    product_definitions: tuple[dict, ...]
    product_relationships: tuple[dict, ...]


def parse_redhat(payload, *, scope):
    if (
        not isinstance(scope, SourceScope)
        or (scope.source, scope.input_kind) != ("Red Hat", "advisories")
        or scope.tenant_id is not None
        or scope.origin not in {"synthetic", "public"}
        or not scope.scope_reference.startswith(BASE)
    ):
        raise ValueError("Red Hat requires its non-tenant public advisory scope")
    source = advisory_file(scope.scope_reference[len(BASE) :])
    feed = parse_csaf(payload, scope=scope)
    if feed.advisory_id != source.advisory_id:
        raise ValueError("Red Hat document identity differs from source path")
    root = _json(payload.decode("utf-8-sig"))
    tree = _object(root.get("product_tree", {}))
    definitions = []

    def retain_product(value):
        value = _object(value)
        helper = _object(value.get("product_identification_helper", {}))
        for key in ("cpe", "purl", "model_numbers", "serial_numbers"):
            if key in helper:
                if key in {"cpe", "purl"}:
                    _text(helper[key])
                else:
                    for item in _array(helper[key]):
                        _text(item)
        definitions.append(value)

    def walk(branches):
        for branch in _array(branches):
            branch = _object(branch)
            if "product" in branch:
                retain_product(branch["product"])
            walk(branch.get("branches", []))

    walk(tree.get("branches", []))
    for product in _array(tree.get("full_product_names", [])):
        retain_product(product)
    relationships = tuple(_array(tree.get("relationships", [])))
    for relation in relationships:
        retain_product(_object(relation).get("full_product_name"))
    identities = {product.product_id for product in feed.products}
    for relation in relationships:
        _text(relation.get("category"))
        for key in ("product_reference", "relates_to_product_reference"):
            if _text(relation.get(key)) not in identities:
                raise ValueError("Unknown Red Hat product relationship endpoint")
    return RedHatFeed(
        **{field.name: getattr(feed, field.name) for field in fields(CsafFeed)},
        source_document=root,
        product_definitions=tuple(definitions),
        product_relationships=relationships,
    )
