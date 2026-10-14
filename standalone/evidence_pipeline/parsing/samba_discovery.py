"""Inspect Samba's security-release index without fetching advertised links.

Only exact publisher CVE announcement paths are eligible for the existing
advisory parser. Other security-announcement paths remain inspectable unresolved
links, never silently discarded or followed as arbitrary URLs.
"""

from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from standalone.evidence_pipeline.parsing.public_inputs import (
    CVE_PATTERN,
    MAX_PUBLIC_RECORDS,
)
from standalone.evidence_pipeline.parsing.samba_advisories import BASE

INDEX_URL = "https://www.samba.org/samba/history/security.html"


@dataclass(frozen=True)
class SambaIndex:
    advisory_ids: tuple[str, ...]
    unresolved_links: tuple[str, ...]


class _Index(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.active = False
        self.tables = 0
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag == "table":
            if self.active:
                raise ValueError("Nested Samba security table")
            if "security_table" in dict(attrs).get("class", "").split():
                self.tables += 1
                self.active = True
        if tag == "a" and self.active:
            hrefs = [value for key, value in attrs if key == "href"]
            if len(hrefs) != 1 or not hrefs[0]:
                raise ValueError("Invalid Samba index link")
            if len(self.links) >= MAX_PUBLIC_RECORDS:
                raise ValueError("Samba index record bound exceeded")
            self.links.append(hrefs[0])

    def handle_endtag(self, tag):
        if tag == "table" and self.active:
            self.active = False


def parse_index(payload):
    if not isinstance(payload, bytes) or not payload:
        raise ValueError("Samba index requires immutable HTML bytes")
    parser = _Index()
    try:
        parser.feed(payload.decode("utf-8-sig"))
        parser.close()
    except UnicodeError as exc:
        raise ValueError("Invalid Samba index encoding") from exc
    if parser.tables != 1 or parser.active:
        raise ValueError("Missing, ambiguous or incomplete Samba security table")
    identities, unresolved = {}, {}
    for href in parser.links:
        resolved = urljoin(INDEX_URL, href)
        path = urlsplit(resolved).path
        if not path.startswith("/samba/security/"):
            continue  # Patch downloads and external CVE lookup links are not advisories.
        name = path.removeprefix("/samba/security/")
        if name.endswith(".html") and CVE_PATTERN.fullmatch(name[:-5]):
            identity = name[:-5]
            expected = BASE + identity + ".html"
            if resolved != expected or href not in (
                expected,
                "/samba/security/" + name,
            ):
                raise ValueError(
                    "Samba advisory link differs from canonical publisher route"
                )
            identities[identity] = None
        else:
            unresolved[href] = None
    if not identities:
        raise ValueError("Samba index contains no supported announcements")
    return SambaIndex(tuple(identities), tuple(unresolved))
