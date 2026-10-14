"""Public MSRC CVRF product-specific fixes and explicit supersedence claims.

Microsoft's Get-MsrcCvrfAffectedSoftware reference treats remediation Type 2 as
KB advice and joins it by ProductID. Product names and fixed builds remain source
labels; this module does not infer device applicability or execute any change.
"""

from dataclasses import dataclass, replace
import re
import json

from standalone.evidence_pipeline.contracts import SourceScope
from standalone.evidence_pipeline.parsing.cvrf_identity import native_identity
from standalone.evidence_pipeline.parsing.cvrf_variants import variants
from standalone.evidence_pipeline.parsing.public_inputs import (
    PublicFeed,
    MAX_PUBLIC_RECORDS,
    _json,
    _object,
    _array,
    _text,
)


@dataclass(frozen=True)
class UpdateClaim:
    cve_id: str | None
    product_id: str
    product_name: str
    source_status_codes: tuple[int, ...]
    patch_reference: str | None
    patch_kb: str | None
    supersedence_reference: str | None
    superseded_kb: str | None
    fixed_build: str | None
    source_remediation: dict
    supersedence_status: str

    @property
    def source_record_id(self):
        return self.cve_id


@dataclass(frozen=True)
class AdvisoryUpdateClaim(UpdateClaim):
    advisory_id: str

    @property
    def source_record_id(self):
        return self.advisory_id


@dataclass(frozen=True)
class CvrfUpdates(PublicFeed):
    records: tuple[UpdateClaim, ...]


def kb(value):
    if value is None or not re.fullmatch(r"(?:KB)?[0-9]{6,8}", value):
        return None
    return value if value.startswith("KB") else "KB" + value


def ids(value):
    result = tuple(_text(item) for item in _array(value))
    # Public CVRF documents repeat identical ProductID references inside one
    # remediation. A repeated reference does not create another relationship;
    # the original list remains in source_remediation and the retained payload.
    return tuple(dict.fromkeys(result))


def without_cyclic_edges(records):
    """Retain cyclic publisher claims as unknown relationships, with no winner.

    Iterative strongly connected components keep long source chains bounded by
    the record limit, without Python recursion or one reachability scan per edge.
    """
    graph, reverse = {}, {}
    for item in records:
        if item.patch_kb is None or item.superseded_kb is None:
            continue
        start = (item.source_record_id, item.product_id, item.patch_kb)
        end = (item.source_record_id, item.product_id, item.superseded_kb)
        graph.setdefault(start, set()).add(end)
        graph.setdefault(end, set())
        reverse.setdefault(end, set()).add(start)
        reverse.setdefault(start, set())
    visited, finished = set(), []
    for start in graph:
        if start in visited:
            continue
        visited.add(start)
        stack = [(start, iter(graph[start]))]
        while stack:
            node, neighbors = stack[-1]
            child = next(neighbors, None)
            if child is None:
                finished.append(node)
                stack.pop()
            elif child not in visited:
                visited.add(child)
                stack.append((child, iter(graph[child])))
    component = {}
    for start in reversed(finished):
        if start in component:
            continue
        component[start] = start
        pending = [start]
        while pending:
            node = pending.pop()
            for parent in reverse[node]:
                if parent not in component:
                    component[parent] = start
                    pending.append(parent)
    return tuple(
        replace(item, superseded_kb=None, supersedence_status="cyclic")
        if item.patch_kb is not None
        and item.superseded_kb is not None
        and component[(item.source_record_id, item.product_id, item.patch_kb)]
        == component[(item.source_record_id, item.product_id, item.superseded_kb)]
        else item
        for item in records
    )


def validate_scope(scope):
    if (
        not isinstance(scope, SourceScope)
        or (scope.source, scope.input_kind) != ("MSRC", "security_updates")
        or scope.tenant_id is not None
        or scope.origin not in ("public", "synthetic")
    ):
        raise ValueError(
            "CVRF requires a public or synthetic MSRC/security_updates scope"
        )


def parse_cvrf_document(root, *, scope):
    products = _document_products(root, scope=scope)
    return _parse_product_records(root, products)


def _document_products(root, *, scope):
    """Validate the envelope and product definitions once per source document."""
    validate_scope(scope)
    if "Vulnerability" not in root:
        # CVRF permits a document with no vulnerability elements. Require its
        # identifying envelope so an unrelated JSON object cannot clear a scope.
        from standalone.evidence_pipeline.parsing.msrc_publications import period

        for field in ("DocumentTitle", "DocumentType"):
            _text(_object(root.get(field)).get("Value"))
        publisher = _object(root.get("DocumentPublisher"))
        if type(publisher.get("Type")) is not int:
            raise ValueError("Missing CVRF publisher type")
        tracking = _object(root.get("DocumentTracking"))
        identity = _text(
            _object(_object(tracking.get("Identification")).get("ID")).get("Value")
        )
        period(identity)
        if not scope.scope_reference.endswith("/" + identity):
            raise ValueError("CVRF empty document identity differs from scope")
        for field in ("Version", "InitialReleaseDate", "CurrentReleaseDate"):
            _text(tracking.get(field))
    products = {}
    for raw in _array(_object(root.get("ProductTree", {})).get("FullProductName", [])):
        raw = _object(raw)
        identity = _text(raw.get("ProductID"))
        if identity in products:
            raise ValueError("Duplicate CVRF product identity")
        products[identity] = _text(raw.get("Value"))
    return products


def _parse_product_records(root, products):
    """Parse records using this document's already validated product map."""
    records = []
    for _, vulnerability, _ in variants(root.get("Vulnerability", [])):
        vulnerability = _object(vulnerability)
        native, cve = native_identity(vulnerability.get("CVE"))
        statuses = {}
        for status in _array(vulnerability.get("ProductStatuses", [])):
            status = _object(status)
            code = status.get("Type")
            if type(code) is not int or code < 0:
                raise ValueError("Invalid CVRF product status code")
            # Historical publisher records can state a status without naming
            # any products. Preserve the raw statement; it establishes no target.
            for identity in ids(status.get("ProductID", [])):
                if identity not in products:
                    raise ValueError("Unknown CVRF status product")
                statuses.setdefault(identity, set()).add(code)
        seen_remediations = set()
        for raw in _array(vulnerability.get("Remediations", [])):
            raw = _object(raw)
            kind = raw.get("Type")
            if type(kind) is not int or kind < 0:
                raise ValueError("Invalid CVRF remediation type")
            targets = ids(raw.get("ProductID", []))
            if set(targets) - products.keys():
                raise ValueError("Unknown CVRF remediation product")
            if kind != 2:
                continue
            reference = _text(
                _object(raw.get("Description", {})).get("Value"),
                optional=True,
                empty=True,
            )
            if reference is not None and not reference.strip():
                reference = None
            supersedence = _text(raw.get("Supercedence"), optional=True)
            fixed_build = _text(raw.get("FixedBuild"), optional=True)
            patch, superseded = kb(reference), kb(supersedence)
            replacement_status = (
                "absent"
                if supersedence is None
                else "explicit"
                if patch is not None and superseded is not None
                else "unstructured"
            )
            # Retain malformed/self-referential claims for inspection; no valid
            # replacement edge can be created from a self-reference.
            if patch is not None and patch == superseded:
                superseded = None
                replacement_status = "self_reference"
            for identity in targets:
                key = (identity, json.dumps(raw, sort_keys=True, default=str))
                if key in seen_remediations:
                    # Duplicate source rows add no independent relationship.
                    continue
                seen_remediations.add(key)
                if len(records) >= MAX_PUBLIC_RECORDS:
                    raise ValueError("CVRF normalized relationship bound exceeded")
                claim_type = UpdateClaim if cve is not None else AdvisoryUpdateClaim
                records.append(
                    claim_type(
                        cve,
                        identity,
                        products[identity],
                        tuple(sorted(statuses.get(identity, ()))),
                        reference,
                        patch,
                        supersedence,
                        superseded,
                        fixed_build,
                        dict(raw),
                        replacement_status,
                        **({"advisory_id": native} if cve is None else {}),
                    )
                )
    return without_cyclic_edges(records)


def parse_cvrf_updates(payload, *, scope):
    validate_scope(scope)
    if not isinstance(payload, bytes) or not payload:
        raise ValueError("CVRF requires bounded immutable bytes")
    root = _json(payload.decode("utf-8-sig"))
    return CvrfUpdates(scope, payload, parse_cvrf_document(root, scope=scope))
