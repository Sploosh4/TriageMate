"""Bounded MSRC CSAF 2.0 facts; no free-text version inference or device matching.

Wire semantics: https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html
This adapter is not yet connected to runtime registration or database persistence.
"""

from dataclasses import dataclass
from datetime import datetime
import re
from urllib.parse import urlsplit

from standalone.evidence_pipeline.contracts import SourceScope
from standalone.evidence_pipeline.parsing.public_inputs import (
    PublicFeed,
    _json,
    _object,
    _array,
    _text,
    _cve,
    _timestamp,
)


@dataclass(frozen=True)
class Product:
    product_id: str
    name: str


@dataclass(frozen=True)
class Remediation:
    category: str
    details: str
    product_ids: tuple[str, ...]
    group_ids: tuple[str, ...]
    url: str | None
    date: datetime | None
    patch_id: str | None


@dataclass(frozen=True)
class Vulnerability:
    cve_id: str
    title: str | None
    product_status: tuple[tuple[str, tuple[str, ...]], ...]
    remediations: tuple[Remediation, ...]


@dataclass(frozen=True)
class CsafFeed(PublicFeed):
    advisory_id: str
    title: str
    publisher: str
    published_at: datetime
    updated_at: datetime
    products: tuple[Product, ...]
    records: tuple[Vulnerability, ...]


def _ids(value):
    ids = tuple(_text(item) for item in _array(value))
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate CSAF product or group reference")
    return ids


def _url(value):
    value = _text(value, optional=True)
    if value is None:
        return None
    parsed = urlsplit(value)
    if (
        parsed.scheme not in ("https", "http")
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        raise ValueError("Invalid CSAF reference URL")
    return value


def _kb(category, url):
    if category != "vendor_fix" or url is None:
        return None
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.netloc.lower() != "support.microsoft.com":
        return None
    match = re.fullmatch(r"/help/([0-9]{6,8})/?", parsed.path)
    return "KB" + match[1] if match else None


def parse_csaf(payload: bytes, *, scope: SourceScope) -> CsafFeed:
    if (
        not isinstance(scope, SourceScope)
        or (scope.source, scope.input_kind)
        not in {
            ("MSRC", "advisories"),
            ("Red Hat", "advisories"),
            ("Cisco", "advisories"),
        }
        or scope.tenant_id is not None
        or scope.origin not in ("public", "synthetic")
    ):
        raise ValueError(
            "CSAF requires a supported public or synthetic non-tenant publisher scope"
        )
    if scope.source == "Cisco" and scope.origin == "public":
        from standalone.evidence_pipeline.parsing.cisco_rss import validate_scope

        validate_scope(scope)
    if not isinstance(payload, bytes) or not payload:
        raise ValueError("CSAF input must be bounded immutable bytes")
    try:
        text = payload.decode("utf-8-sig")
    except UnicodeError as error:
        raise ValueError("Invalid CSAF encoding") from error
    if "\x00" in text:
        raise ValueError("NUL in CSAF input")
    root = _json(text)
    document = _object(root.get("document"))
    if document.get("csaf_version") != "2.0":
        raise ValueError("Unsupported CSAF version; do not guess remediation semantics")
    tracking = _object(document.get("tracking"))
    products = {}

    def product(value):
        value = _object(value)
        identity = _text(value.get("product_id"))
        name = _text(value.get("name"))
        if identity in products:
            raise ValueError("Duplicate CSAF product ID")
        products[identity] = Product(identity, name)

    def branches(items):
        for item in _array(items):
            item = _object(item)
            if "product" in item:
                product(item["product"])
            branches(item.get("branches", []))

    tree = _object(root.get("product_tree", {}))
    branches(tree.get("branches", []))
    for item in _array(tree.get("full_product_names", [])):
        product(item)
    for relationship in _array(tree.get("relationships", [])):
        product(_object(relationship).get("full_product_name"))

    def check_products(ids):
        if set(ids) - products.keys():
            raise ValueError("Unknown CSAF product reference")
        return ids

    groups = {}
    for item in _array(tree.get("product_groups", [])):
        item = _object(item)
        identity = _text(item.get("group_id"))
        if identity in groups:
            raise ValueError("Duplicate CSAF group ID")
        groups[identity] = check_products(_ids(item.get("product_ids")))
    records = []
    seen = set()
    for item in _array(root.get("vulnerabilities", [])):
        item = _object(item)
        cve = _cve(item.get("cve"))
        if cve in seen:
            raise ValueError("Duplicate CSAF CVE")
        seen.add(cve)
        states = tuple(
            (key, check_products(_ids(ids)))
            for key, ids in _object(item.get("product_status", {})).items()
        )
        remedies = []
        for remedy in _array(item.get("remediations", [])):
            remedy = _object(remedy)
            category = _text(remedy.get("category"))
            if category not in (
                "vendor_fix",
                "mitigation",
                "workaround",
                "none_available",
                "no_fix_planned",
            ):
                raise ValueError("Unsupported CSAF remediation category")
            direct = check_products(_ids(remedy.get("product_ids", [])))
            group_ids = _ids(remedy.get("group_ids", []))
            if set(group_ids) - groups.keys():
                raise ValueError("Unknown CSAF group reference")
            targets = tuple(
                sorted(set(direct).union(*(groups[group] for group in group_ids)))
            )
            if not targets:
                raise ValueError("CSAF remediation needs explicit product targets")
            url = _url(remedy.get("url"))
            remedies.append(
                Remediation(
                    category,
                    _text(remedy.get("details")),
                    targets,
                    group_ids,
                    url,
                    _timestamp(remedy.get("date"), optional=True),
                    _kb(category, url) if scope.source == "MSRC" else None,
                )
            )
        records.append(
            Vulnerability(
                cve, _text(item.get("title"), optional=True), states, tuple(remedies)
            )
        )
    return CsafFeed(
        scope,
        payload,
        _text(tracking.get("id")),
        _text(document.get("title")),
        _text(_object(document.get("publisher")).get("name")),
        _timestamp(tracking.get("initial_release_date")),
        _timestamp(tracking.get("current_release_date")),
        tuple(products.values()),
        tuple(records),
    )
