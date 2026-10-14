"""Bounded OSV package discovery; query matches are not device applicability.

Retains exact page bytes and the explicit package query. No package identity is
inferred from installed-software display names. No database writes or retries.
Contract: https://google.github.io/osv.dev/post-v1-query/
"""

from dataclasses import dataclass
import json

from standalone.evidence_pipeline.source_json import encode_source_records
from standalone.evidence_pipeline.contracts import SourceScope, utc
from standalone.evidence_pipeline.parsing.osv import OsvRecord, parse_osv
from standalone.evidence_pipeline.parsing.public_inputs import _array, _json
from standalone.evidence_pipeline.contracts import PublicDownload

URL = "https://api.osv.dev/v1/query"
MAX_PAGES = 100


def _text(value):
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > 4096
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise ValueError("OSV query requires bounded nonempty text")
    return value


def package_query(*, name=None, ecosystem=None, purl=None, version=None):
    """Use a supplied ecosystem identity or package URL without case folding."""
    if purl is not None:
        if name is not None or ecosystem is not None:
            raise ValueError("Use package name/ecosystem or purl, not both")
        purl = _text(purl)
        path = purl.split("?", 1)[0].split("#", 1)[0]
        if not path.startswith("pkg:") or "/" not in path[4:]:
            raise ValueError("OSV package URL requires pkg:type/name")
        if version is not None and "@" in path.rsplit("/", 1)[-1]:
            raise ValueError("OSV version cannot be supplied twice")
        package = dict(purl=purl)
    else:
        package = dict(name=_text(name), ecosystem=_text(ecosystem))
    query = dict(package=package)
    if version is not None:
        query["version"] = _text(version)
    return query


def validate_scope(scope, *, synthetic=False):
    if (
        not isinstance(scope, SourceScope)
        or (scope.source, scope.input_kind) != ("OSV", "advisories")
        or scope.origin not in ({"public", "synthetic"} if synthetic else {"public"})
        or scope.tenant_id is not None
        or scope.scope_reference != URL
    ):
        raise ValueError("OSV query requires a non-tenant query scope")


def query_bytes(value):
    """Validate stored query fields as strictly as the initial request."""
    if not isinstance(value, dict) or set(value) - {"package", "version"}:
        raise ValueError("Unsupported OSV query fields")
    package = value.get("package")
    if not isinstance(package, dict) or set(package) - {"name", "ecosystem", "purl"}:
        raise ValueError("Unsupported OSV package fields")
    normalized = package_query(**package, version=value.get("version"))
    if normalized != value:
        raise ValueError("OSV query fields do not match their normalized form")
    encoded = json.dumps(normalized, sort_keys=True).encode()
    if len(encoded) > 32768:
        raise ValueError("OSV query exceeds encoded byte limit")
    return encoded


@dataclass(frozen=True)
class QueryPage:
    request: bytes
    response: PublicDownload
    records: tuple[OsvRecord, ...]
    next_page_token: str | None


@dataclass(frozen=True)
class QueryResult:
    scope: SourceScope
    query: bytes
    pages: tuple[QueryPage, ...]


def parse_page(scope, request, response):
    raw = _json(response.payload.decode("utf-8-sig"))
    records = tuple(
        parse_osv(encode_source_records(item), scope=scope).records[0]
        for item in _array(raw.get("vulns", []))
    )
    token = raw.get("next_page_token")
    if token == "":
        token = None
    if token is not None:
        token = _text(token)
    return QueryPage(request, response, records, token)


def parse_pages(*, scope, query, responses):
    """Reconstruct a complete chain from retained bytes, never calling HTTP."""
    validate_scope(scope, synthetic=True)
    original = query_bytes(query)
    request = dict(query)
    if not isinstance(responses, (list, tuple)) or not 1 <= len(responses) <= MAX_PAGES:
        raise ValueError("OSV query requires a bounded complete page chain")

    pages, tokens = [], set()
    previous_finish = None
    for index, response in enumerate(responses):
        if (
            not isinstance(response, PublicDownload)
            or response.url != URL
            or not isinstance(response.wire, bytes)
            or response.payload != response.wire
            or not response.wire
        ):
            raise ValueError("OSV query page violates source boundary")
        started, finished = utc(response.started_at), utc(response.finished_at)
        if finished < started or (
            previous_finish is not None and started < previous_finish
        ):
            raise ValueError("OSV query page times are out of order")
        previous_finish = finished

        page = parse_page(scope, json.dumps(request, sort_keys=True).encode(), response)
        token = page.next_page_token
        if token is not None and token in tokens:
            raise ValueError("OSV query repeated a continuation token")
        if (token is None) != (index == len(responses) - 1):
            raise ValueError("OSV query page chain is incomplete or has extra pages")
        if token is not None:
            tokens.add(token)
            request["page_token"] = token
        pages.append(page)
    return QueryResult(scope, original, tuple(pages))
