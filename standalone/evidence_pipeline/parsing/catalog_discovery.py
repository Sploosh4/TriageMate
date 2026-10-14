"""Public Catalog KB search identities; search hits never establish applicability.

The publisher exposes HTML search results, not an asserted stable JSON API. Keep
result count/page coverage explicit; do not treat a first page as all updates.
"""

from dataclasses import dataclass
from html.parser import HTMLParser
import re

from standalone.evidence_pipeline.parsing.update_catalog import update_id, endpoint

BASE = "https://www.catalog.update.microsoft.com/Search.aspx?q="
KB = re.compile(r"KB[0-9]{4,10}\Z")
ROW = re.compile(r"([0-9a-f-]{36})_R([0-9]+)\Z")
COUNT = re.compile(r"([0-9]+) - ([0-9]+) of ([0-9]+) \(page ([0-9]+) of ([0-9]+)\)\Z")


def search_url(kb, *, page=1):
    if not isinstance(kb, str) or not KB.fullmatch(kb):
        raise ValueError("Catalog discovery requires one canonical KB identifier")
    if type(page) is not int or page < 1:
        raise ValueError("Catalog search page must be a positive integer")
    # Publisher Search.aspx uses zero-based `p`; evidence uses one-based pages.
    return BASE + kb + (f"&p={page - 1}" if page > 1 else "")


@dataclass(frozen=True)
class SearchHit:
    update_id: str
    title: str
    products: str
    classification: str
    updated_at: str
    version: str

    @property
    def url(self):
        return endpoint(self.update_id)


@dataclass(frozen=True)
class SearchResults:
    kb: str
    hits: tuple[SearchHit, ...]
    first: int
    last: int
    total: int
    page: int
    pages: int

    @property
    def complete(self):
        return (
            self.first == self.last == self.total == 0 and self.page == self.pages == 1
        ) or (self.first == 1 and self.last == self.total and self.pages == 1)


@dataclass(frozen=True)
class SearchCoverage:
    kb: str
    hits: tuple[SearchHit, ...]
    total: int
    collected_pages: int
    total_pages: int
    complete: bool


def combine_pages(pages):
    """Validate a contiguous saved prefix without mistaking it for full coverage.

    A changing publisher result set is not repaired by deduplicating it: gaps,
    repeated identities and changed totals reject this search attempt instead.
    """
    pages = tuple(pages)
    if not pages or any(not isinstance(page, SearchResults) for page in pages):
        raise ValueError("Catalog coverage requires parsed search pages")
    first = pages[0]
    hits, seen, previous_last = [], set(), 0
    for number, page in enumerate(pages, 1):
        if (
            page.kb != first.kb
            or page.total != first.total
            or page.pages != first.pages
            or page.page != number
            or number > page.pages
        ):
            raise ValueError("Catalog page identity or totals changed")
        if page.total == 0:
            if len(pages) != 1 or not page.complete or page.hits:
                raise ValueError("Contradictory Catalog empty search")
        elif (
            page.first != previous_last + 1
            or page.last - page.first + 1 != len(page.hits)
            or (number < page.pages and page.last >= page.total)
            or (number == page.pages and page.last != page.total)
        ):
            raise ValueError("Catalog page sequence has a gap or overlap")
        for hit in page.hits:
            if hit.update_id in seen:
                raise ValueError("Catalog search repeats an update across pages")
            seen.add(hit.update_id)
            hits.append(hit)
        previous_last = page.last
    return SearchCoverage(
        first.kb,
        tuple(hits),
        first.total,
        len(pages),
        first.pages,
        len(pages) == first.pages and len(hits) == first.total,
    )


class SearchHTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.query = None
        self.count = None
        self.capture_count = False
        self.row = None
        self.cell = None
        self.rows = []
        self.table = False
        self.table_seen = False
        self.empty_fields = {}
        self.empty_capture = None

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        identity = attributes.get("id", "")
        if identity in {
            "ctl00_catalogBody_noResultText",
            "ctl00_catalogBody_searchString",
        }:
            if tag != "span" or identity in self.empty_fields or self.empty_capture:
                raise ValueError("Malformed Catalog empty-result evidence")
            self.empty_fields[identity] = []
            self.empty_capture = identity
        if identity == "ctl00_searchTextBox":
            if self.query is not None:
                raise ValueError("Duplicate Catalog search identity")
            self.query = attributes.get("value")
        if identity == "ctl00_catalogBody_searchDuration":
            if self.count is not None:
                raise ValueError("Duplicate Catalog result count")
            self.count = []
            self.capture_count = True
        if identity == "ctl00_catalogBody_updateMatches":
            if tag != "table" or self.table_seen:
                raise ValueError("Duplicate or malformed Catalog result table")
            self.table = self.table_seen = True
        if not self.table:
            return
        if tag == "tr":
            match = ROW.fullmatch(identity)
            if match:
                if self.row is not None:
                    raise ValueError("Nested Catalog result row")
                self.row = {"id": update_id(match[1]), "cells": {}, "link": False}
            elif identity != "headerRow":
                raise ValueError("Unknown Catalog result row")
        if self.row is None:
            return
        if tag == "td":
            match = re.fullmatch(
                re.escape(self.row["id"]) + r"_C([0-7])_R[0-9]+", identity
            )
            if not match or self.cell is not None or match[1] in self.row["cells"]:
                raise ValueError("Malformed Catalog result cell")
            self.cell = match[1]
            self.row["cells"][self.cell] = []
        if tag == "a" and self.cell == "1":
            if (
                self.row["link"]
                or attributes.get("onclick") != f'goToDetails("{self.row["id"]}");'
            ):
                raise ValueError("Catalog title link identity differs")
            self.row["link"] = True

    def handle_endtag(self, tag):
        if tag == "span":
            self.empty_capture = None
        if tag == "span" and self.capture_count:
            self.capture_count = False
        if tag == "td":
            self.cell = None
        if tag == "tr" and self.row is not None:
            if not self.row["link"] or set(self.row["cells"]) != set("01234567"):
                raise ValueError("Incomplete Catalog result row")
            self.rows.append(self.row)
            self.row = None
        if tag == "table" and self.table:
            if self.row is not None:
                raise ValueError("Unclosed Catalog result row")
            self.table = False

    def handle_data(self, data):
        if self.empty_capture is not None:
            self.empty_fields[self.empty_capture].append(data)
        if self.capture_count:
            self.count.append(data)
        if self.row is not None and self.cell is not None:
            self.row["cells"][self.cell].append(data)


def parse_search(payload, *, kb):
    search_url(kb)
    if not isinstance(payload, bytes) or not payload:
        raise ValueError("Catalog search requires response bytes")
    parser = SearchHTML()
    parser.feed(payload.decode("utf-8-sig"))
    parser.close()
    if "ctl00_catalogBody_noResultText" in parser.empty_fields:
        fields = {
            key: " ".join("".join(value).split())
            for key, value in parser.empty_fields.items()
        }
        if (
            parser.query != kb
            or parser.table_seen
            or parser.count is not None
            or parser.empty_capture is not None
            or fields
            != {
                "ctl00_catalogBody_noResultText": "We did not find any results for",
                "ctl00_catalogBody_searchString": '"' + kb + '"',
            }
        ):
            raise ValueError("Catalog empty-result identity or coverage differs")
        return SearchResults(kb, (), 0, 0, 0, 1, 1)
    count = COUNT.fullmatch(" ".join("".join(parser.count or []).split()))
    if parser.query != kb or not parser.table_seen or parser.table or not count:
        raise ValueError("Catalog search identity or coverage is missing")
    first, last, total, page, pages = map(int, count.groups())
    if not (
        1 <= first <= last <= total
        and 1 <= page <= pages
        and last - first + 1 == len(parser.rows)
    ):
        raise ValueError("Catalog result count differs from rows")
    if (page == 1 and first != 1) or (page == pages and last != total):
        raise ValueError("Catalog page coverage is inconsistent")
    hits = []
    seen = set()
    for row in parser.rows:
        fields = [" ".join("".join(row["cells"][str(i)]).split()) for i in range(1, 6)]
        if row["id"] in seen or any(not field for field in fields):
            raise ValueError("Duplicate or empty Catalog search result")
        seen.add(row["id"])
        hits.append(SearchHit(row["id"], *fields))
    return SearchResults(kb, tuple(hits), first, last, total, page, pages)
