"""Synthetic-only HTTP Server CVE 4.0 export contract pending reuse clarification.

Preserve the original version operators and timeline; do not infer a fixed
release from prose, enumerated affected versions or a release-candidate mention.
"""

from dataclasses import dataclass

from standalone.evidence_pipeline.contracts import SourceScope
from standalone.evidence_pipeline.parsing.public_inputs import (
    PublicFeed,
    CVE_PATTERN,
    _json,
    _object,
    _array,
    _text,
)

BASE = "https://httpd.apache.org/security/json/"


@dataclass(frozen=True)
class HttpdRecord:
    cve_id: str
    raw: dict
    products: tuple[dict, ...]

    @property
    def source_record_id(self):
        return self.cve_id

    @property
    def cve_ids(self):
        return (self.cve_id,)


@dataclass(frozen=True)
class HttpdFeed(PublicFeed):
    records: tuple[HttpdRecord, ...]


def parse_httpd(payload, *, scope):
    if (
        not isinstance(scope, SourceScope)
        or (scope.source, scope.input_kind) != ("Apache HTTP Server", "advisories")
        or scope.origin not in {"synthetic", "public"}
        or scope.tenant_id is not None
        or not scope.scope_reference.startswith(BASE)
    ):
        raise ValueError(
            "HTTP Server currently requires its public or synthetic source scope"
        )
    native = scope.scope_reference[len(BASE) :].removesuffix(".json")
    if (
        not CVE_PATTERN.fullmatch(native)
        or scope.scope_reference != BASE + native + ".json"
    ):
        raise ValueError("Invalid HTTP Server advisory path")
    if not isinstance(payload, bytes) or not payload:
        raise ValueError("HTTP Server payload must be bounded immutable bytes")
    root = _json(payload.decode("utf-8-sig"))
    if (root.get("data_type"), root.get("data_format"), root.get("data_version")) != (
        "CVE",
        "MITRE",
        "4.0",
    ):
        raise ValueError("Unsupported HTTP Server export format")
    metadata = _object(root.get("CVE_data_meta"))
    if metadata.get("ID") != native:
        raise ValueError("HTTP Server response identity differs from source path")
    _text(metadata.get("STATE"))
    products = []
    vendors = _object(_object(root.get("affects", {})).get("vendor", {}))
    for vendor in _array(vendors.get("vendor_data", [])):
        vendor = _object(vendor)
        _text(vendor.get("vendor_name"))
        for product in _array(_object(vendor.get("product")).get("product_data")):
            product = _object(product)
            _text(product.get("product_name"))
            for version in _array(_object(product.get("version")).get("version_data")):
                version = _object(version)
                _text(version.get("version_value"))
                for key in ("version_name", "version_affected"):
                    if key in version:
                        _text(version[key])
            products.append(dict(vendor_name=vendor["vendor_name"], product=product))
    return HttpdFeed(scope, payload, (HttpdRecord(native, root, tuple(products)),))
