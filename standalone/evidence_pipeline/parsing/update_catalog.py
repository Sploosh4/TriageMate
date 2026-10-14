"""Read public Catalog detail metadata; never download or execute update packages."""

from datetime import datetime
from html.parser import HTMLParser
import re
from uuid import UUID

BASE = "https://www.catalog.update.microsoft.com/ScopedViewInline.aspx?updateid="
RELATIVE = "ScopedViewInline.aspx?updateid="
FIELDS = {
    "title": ("ScopedViewHandler_titleText", ""),
    "updated_at": ("ScopedViewHandler_date", ""),
    "description": ("ScopedViewHandler_desc", ""),
    "architecture": ("archDiv", "Architecture:"),
    "classification": ("classificationDiv", "Classification:"),
    "products": ("productsDiv", "Supported products:"),
    "kb_articles": ("kbDiv", "KB article numbers:"),
}
SECTIONS = {"supersedesInfo": "replaces", "supersededbyInfo": "replaced_by"}


def update_id(value):
    if not isinstance(value, str) or str(UUID(value)) != value:
        raise ValueError("Catalog update ID must be a canonical UUID")
    return value


def endpoint(identity):
    return BASE + update_id(identity)


class DetailHTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.text = {}
        self.links = {key: [] for key in SECTIONS}
        self.targets = (
            {value[0] for value in FIELDS.values()}
            | set(SECTIONS)
            | {"ScopedViewHandler_UpdateID"}
        )

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        identity = attributes.get("id")
        if identity in self.targets:
            if identity in self.text:
                raise ValueError("Duplicate Catalog metadata section")
            self.text[identity] = []
        else:
            identity = None
        link = None
        sections = [item[1] for item in self.stack if item[1] in SECTIONS]
        if sections and tag == "div" and self.stack[-1][1] in SECTIONS:
            link = {"update_id": None, "title": []}
            self.links[sections[-1]].append(link)
        if sections and tag == "a":
            href = attributes.get("href", "")
            if not href.startswith(RELATIVE):
                raise ValueError("Unexpected Catalog replacement reference")
            native = update_id(href[len(RELATIVE) :])
            parent_items = [item[2] for item in self.stack if item[2] is not None]
            if parent_items:
                if parent_items[-1]["update_id"] is not None:
                    raise ValueError("Multiple identities in Catalog replacement")
                parent_items[-1]["update_id"] = native
            else:
                link = {"update_id": native, "title": []}
                self.links[sections[-1]].append(link)
        if tag not in {
            "area",
            "base",
            "br",
            "col",
            "embed",
            "hr",
            "img",
            "input",
            "link",
            "meta",
            "param",
            "source",
            "track",
            "wbr",
        }:
            self.stack.append((tag, identity, link))

    def handle_endtag(self, tag):
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index][0] == tag:
                del self.stack[index:]
                break

    def handle_data(self, data):
        for _, identity, link in self.stack:
            if identity is not None:
                self.text[identity].append(data)
            if link is not None:
                link["title"].append(data)

    def value(self, identity):
        if identity not in self.text:
            raise ValueError("Missing Catalog metadata section")
        return " ".join("".join(self.text[identity]).split())


def parse_detail(payload, *, identity):
    identity = update_id(identity)
    if not isinstance(payload, bytes) or not payload:
        raise ValueError("Catalog detail requires source bytes")
    parser = DetailHTML()
    try:
        parser.feed(payload.decode("utf-8-sig"))
        parser.close()
    except (UnicodeError, RecursionError) as exc:
        raise ValueError("Invalid Catalog HTML") from exc
    if any(item[1] is not None for item in parser.stack):
        raise ValueError("Incomplete Catalog metadata section")
    if parser.value("ScopedViewHandler_UpdateID") != identity:
        raise ValueError("Catalog response identifies a different update")
    result = {"update_id": identity}
    for field, (element, label) in FIELDS.items():
        value = parser.value(element)
        if not value.startswith(label):
            raise ValueError("Catalog metadata label changed")
        result[field] = value[len(label) :].strip()
    if not result["title"] or not re.fullmatch(
        r"\d{1,2}/\d{1,2}/\d{4}", result["updated_at"]
    ):
        raise ValueError("Catalog title or date is missing or changed")
    try:
        datetime.strptime(result["updated_at"], "%m/%d/%Y")
    except ValueError as exc:
        raise ValueError("Invalid Catalog publication date") from exc
    for element, field in SECTIONS.items():
        text = parser.value(element)
        links = parser.links[element]
        if not links and text.casefold() not in {"n/a", "none"}:
            # An empty/missing/malformed section is not proof of no replacements.
            raise ValueError("Catalog replacement section is not explicit")
        result[field] = []
        seen = set()
        for link in links:
            title = " ".join("".join(link["title"]).split())
            key = (link["update_id"], title)
            if not title or link["update_id"] == identity or key in seen:
                raise ValueError("Invalid or duplicate Catalog replacement identity")
            seen.add(key)
            result[field].append({"update_id": link["update_id"], "title": title})
    return result
