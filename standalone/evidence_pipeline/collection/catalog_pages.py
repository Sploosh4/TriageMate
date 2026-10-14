"""Immutable Catalog page chain shared by collection and scheduler proof."""

from datetime import datetime, timezone
import hashlib
import json

from standalone.evidence_pipeline.parsing.catalog_discovery import (
    combine_pages,
    parse_search,
    search_url,
)
from standalone.evidence_pipeline.collection.snapshot_bundle import (
    _private_directory,
    _read,
    _write,
    _sync_directory,
)


def saved_pages(
    root,
    *,
    request,
    kb,
    first_payload,
    download=None,
    synthetic_pages=None,
    page_limit=10,
):
    """Read a contiguous prefix; optionally acquire missing pages once.

    An existing partial page directory never triggers a replacement request.
    Budgets count all pages, including already saved ones. Proof callers supply
    neither a downloader nor fixtures and validate all retained pages.
    """
    if type(page_limit) is not int or not 1 <= page_limit <= 100:
        raise ValueError("Invalid Catalog search page budget")
    fixtures = {} if synthetic_pages is None else synthetic_pages
    if not isinstance(fixtures, dict) or any(
        type(key) is not int or key < 2 or not isinstance(value, bytes)
        for key, value in fixtures.items()
    ):
        raise ValueError("Catalog page fixtures require numbered response bytes")
    if fixtures and request["origin"] != "synthetic":
        raise ValueError("Synthetic Catalog pages cannot be relabelled public")
    if download is not None and request["origin"] != "public":
        raise ValueError("Synthetic Catalog pages cannot use network")
    _private_directory(root)
    pages = [parse_search(first_payload, kb=kb)]
    fingerprints = [hashlib.sha256(first_payload).hexdigest()]
    coverage = combine_pages(pages)
    existing = set()
    for path in root.glob("page-*"):
        suffix = path.name.removeprefix("page-")
        if not suffix.isdecimal() or str(int(suffix)) != suffix:
            raise ValueError("Invalid Catalog saved page name")
        existing.add(int(suffix))
    if sorted(existing) != list(range(2, len(existing) + 2)):
        raise ValueError("Catalog saved pages have a gap")
    if any(number > coverage.total_pages for number in existing):
        raise ValueError("Catalog saved pages exceed publisher coverage")
    if any(number > coverage.total_pages for number in fixtures):
        raise ValueError("Catalog fixture page exceeds publisher coverage")
    for number in range(2, coverage.total_pages + 1):
        directory = root / f"page-{number}"
        page_request = dict(
            request,
            source_url=search_url(kb, page=number),
            page=number,
            previous_fingerprint=fingerprints[-1],
        )
        if number not in existing:
            if number > page_limit or (download is None and number not in fixtures):
                break
            directory.mkdir(mode=0o700)
            _sync_directory(root)
            _write(
                directory / "request.json",
                json.dumps(page_request, sort_keys=True).encode(),
            )
            _sync_directory(directory)
            payload = (
                fixtures[number]
                if number in fixtures
                else download(page_request["source_url"]).payload
            )
            _write(directory / "search.html", payload)
            _write(
                directory / "receipt.json",
                json.dumps(
                    dict(
                        page_request,
                        fingerprint=hashlib.sha256(payload).hexdigest(),
                        collected_at=datetime.now(timezone.utc).isoformat(),
                    ),
                    sort_keys=True,
                ).encode(),
            )
            _sync_directory(directory)
        _private_directory(directory)
        if json.loads(_read(directory / "request.json", 16384)) != page_request:
            raise ValueError("Catalog page request differs from saved chain")
        payload = _read(directory / "search.html")
        fingerprint = hashlib.sha256(payload).hexdigest()
        receipt = json.loads(_read(directory / "receipt.json", 16384))
        collected = receipt.get("collected_at")
        if (
            not isinstance(collected, str)
            or datetime.fromisoformat(collected).utcoffset() is None
        ):
            raise ValueError("Catalog page requires an explicit collection clock")
        if receipt != dict(
            page_request, fingerprint=fingerprint, collected_at=collected
        ):
            raise ValueError("Catalog page receipt mismatch")
        if number in fixtures and fixtures[number] != payload:
            raise ValueError("Catalog page fixture differs from saved evidence")
        pages.append(parse_search(payload, kb=kb))
        fingerprints.append(fingerprint)
        coverage = combine_pages(pages)
    digest = (
        fingerprints[0]
        if len(fingerprints) == 1
        else hashlib.sha256(
            json.dumps(fingerprints, separators=(",", ":")).encode()
        ).hexdigest()
    )
    return coverage, digest
