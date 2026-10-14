"""Cisco CSAF claims from canonical publisher routes.

Publisher example uses a lowercase filename and mixed-case tracking ID:
https://www.cisco.com/.well-known/csaf/2024/cisco-sa-ap-dos-h9tggx6w.json
Keep native text and structured claims; do not interpret fixed-release prose.
"""

import json

from standalone.evidence_pipeline.contracts import SourceScope
from standalone.evidence_pipeline.parsing.csaf import parse_csaf
from standalone.evidence_pipeline.parsing.cisco_discovery import BASE, advisory_file
from standalone.evidence_pipeline.parsing.public_inputs import _object, _array, _text


def parse_cisco(payload, *, scope):
    if (
        not isinstance(scope, SourceScope)
        or (scope.source, scope.input_kind) != ("Cisco", "advisories")
        or scope.origin not in {"synthetic", "public"}
        or scope.tenant_id is not None
    ):
        raise ValueError("Cisco requires public or synthetic non-tenant scope")
    legacy = scope.scope_reference.startswith(BASE)
    if legacy:
        if scope.origin != "synthetic":
            raise ValueError("Legacy Cisco route remains synthetic only")
        identity = advisory_file(scope.scope_reference[len(BASE) :]).advisory_id
    else:
        from standalone.evidence_pipeline.parsing.cisco_rss import validate_scope

        identity = validate_scope(scope)
    feed = parse_csaf(payload, scope=scope)
    if (
        not feed.advisory_id.isascii()
        or (feed.advisory_id.lower() if legacy else feed.advisory_id) != identity
    ):
        raise ValueError("Cisco document identity differs from source path")
    tree = _object(json.loads(feed.raw_payload).get("product_tree", {}))
    identities = {product.product_id for product in feed.products}
    for relation in _array(tree.get("relationships", [])):
        relation = _object(relation)
        _text(relation.get("category"))
        for key in ("product_reference", "relates_to_product_reference"):
            if _text(relation.get(key)) not in identities:
                raise ValueError("Unknown Cisco product relationship endpoint")
    return feed
