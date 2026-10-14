"""Bounded Samba announcement parsing; prose is retained without applicability guesses.

Wire reference: https://www.samba.org/samba/security/CVE-2025-10230.html
No transport registration or advisory redistribution authority is implied.
"""

from dataclasses import dataclass
from html.parser import HTMLParser
import re

from standalone.evidence_pipeline.parsing.public_inputs import CVE_PATTERN

BASE = "https://www.samba.org/samba/security/"


@dataclass(frozen=True)
class SambaNotice:
    cve_id: str
    subject: str
    versions_text: str
    summary: str | None
    sections: tuple[tuple[str, str], ...]
    announcement_text: str
    raw_payload: bytes


class _Announcement(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.active = None
        self.headings = []
        self.blocks = []
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if self.active is not None:
            raise ValueError("Unexpected markup inside Samba announcement text")
        if tag in ("h2", "pre"):
            self.active = tag
            self.parts = []

    def handle_endtag(self, tag):
        if tag == self.active:
            target = self.headings if tag == "h2" else self.blocks
            target.append("".join(self.parts))
            self.active = None

    def handle_data(self, data):
        if self.active is not None:
            self.parts.append(data)


def parse_samba(payload: bytes, *, cve_id: str) -> SambaNotice:
    if not isinstance(cve_id, str) or not CVE_PATTERN.fullmatch(cve_id):
        raise ValueError("Invalid Samba CVE identity")
    if not isinstance(payload, bytes) or not payload:
        raise ValueError("Samba announcement requires bounded immutable bytes")
    try:
        document = payload.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("Invalid Samba announcement encoding") from exc
    parser = _Announcement()
    parser.feed(document)
    parser.close()
    if (
        parser.active is not None
        or parser.headings != [cve_id + ".html:"]
        or len(parser.blocks) != 1
    ):
        raise ValueError("Unsupported or mismatched Samba announcement layout")
    body = parser.blocks[0].replace("\r\n", "\n")
    # Header fields can wrap; parse only the leading equals-prefixed block.
    header = re.match(r"\s*=+\n(?P<fields>(?:==[^\n]*\n)+)=+\n", body)
    if header is None:
        raise ValueError("Missing Samba announcement header")
    fields = {}
    current = None
    for line in header["fields"].splitlines():
        value = line[2:].strip()
        field = re.fullmatch(r"(Subject|CVE ID#|Versions|Summary):\s*(.*)", value)
        if field:
            current = field[1]
            if current in fields:
                raise ValueError("Duplicate Samba announcement field")
            fields[current] = field[2]
        elif value:
            if current is None:
                raise ValueError("Unrecognized Samba announcement field")
            fields[current] += " " + value
    if fields.get("CVE ID#") != cve_id or any(
        not fields.get(name) for name in ("Subject", "Versions")
    ):
        raise ValueError("Missing or mismatched Samba announcement identity/fields")
    headings = list(re.finditer(r"^={3,}\n([^\n=]+)\n={3,}\n", body, re.M))
    sections = tuple(
        (
            item[1].strip(),
            body[
                item.end() : headings[index + 1].start()
                if index + 1 < len(headings)
                else len(body)
            ].strip(),
        )
        for index, item in enumerate(headings)
    )
    if not any(name == "Description" and value for name, value in sections):
        raise ValueError("Missing Samba announcement description")
    return SambaNotice(
        cve_id,
        fields["Subject"],
        fields["Versions"],
        fields.get("Summary"),
        sections,
        body,
        payload,
    )
