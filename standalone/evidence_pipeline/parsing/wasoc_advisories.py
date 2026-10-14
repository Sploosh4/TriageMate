"""WA SOC's Apache-2.0 public repository; narrative is not patch applicability.

Official site links https://github.com/wagov/wasocshared, whose root LICENSE is
Apache-2.0. Routes bind a complete commit and an advisory file, never the website.
No publication date, affected version or exploitation status is inferred from prose.
"""

from dataclasses import dataclass
import re
from urllib.parse import quote, unquote_to_bytes

from standalone.evidence_pipeline.contracts import SourceScope
from standalone.evidence_pipeline.parsing.github_discovery import object_id
from standalone.evidence_pipeline.parsing.public_inputs import CVE_PATTERN

BASE = "https://raw.githubusercontent.com/wagov/wasocshared/"
PATH = re.compile(
    r"docs/advisories/(?P<id>[0-9]{9,14})-[^/\\\x00-\x1f\x7f?#%]{1,240}\.md\Z"
)
CVE_REFERENCE = re.compile(
    r"(?<![A-Za-z0-9_-])CVE-[0-9]{4}-[0-9]{4,19}(?![A-Za-z0-9_-])"
)


def repository_endpoint(commit, path, advisory_id):
    object_id(commit)
    match = PATH.fullmatch(path) if isinstance(path, str) else None
    if match is None or match["id"] != advisory_id:
        raise ValueError("WA SOC repository path differs from advisory identity")
    return BASE + commit + "/" + quote(path, safe="/")


@dataclass(frozen=True)
class WasocNotice:
    advisory_id: str
    title: str
    referenced_cves: tuple[str, ...]
    sections: tuple[tuple[str, str], ...]
    raw_payload: bytes


def validate_scope(scope):
    """Validate authority and return the pinned native identity before fetching."""
    if (
        not isinstance(scope, SourceScope)
        or (scope.source, scope.input_kind) != ("WA SOC", "advisories")
        or scope.origin not in {"public", "synthetic"}
        or scope.tenant_id is not None
        or not scope.scope_reference.startswith(BASE)
    ):
        raise ValueError("WA SOC requires its non-tenant public repository scope")
    try:
        relative = unquote_to_bytes(scope.scope_reference[len(BASE) :]).decode("utf-8")
    except UnicodeError as exc:
        raise ValueError("Invalid WA SOC encoded path") from exc
    parts = relative.split("/", 1)
    match = PATH.fullmatch(parts[1]) if len(parts) == 2 else None
    if (
        match is None
        or repository_endpoint(parts[0], parts[1], match["id"]) != scope.scope_reference
    ):
        raise ValueError("Invalid pinned WA SOC advisory route")
    return match["id"]


def source_heading(payload):
    line = payload.decode("utf-8-sig").splitlines()[0]
    heading = re.fullmatch(r"#{1,6} (\S.*) - ([0-9]{9,14})", line)
    if heading is None:
        heading = re.fullmatch(r"#{1,6} (\S.*?)\s*-\s*([0-9]{9,14})\s*", line)
    if heading is not None:
        return heading[1], heading[2]
    title = re.fullmatch(r"#{1,6} (\S.*)", line)
    if title is not None:
        return title[1], None
    raise ValueError("WA SOC document requires a nonempty title heading")


def parse_wasoc(payload, *, scope):
    advisory_id = validate_scope(scope)
    if not isinstance(payload, bytes):
        raise ValueError("WA SOC requires original Markdown bytes")
    try:
        text = payload.decode("utf-8-sig")
    except UnicodeError as exc:
        raise ValueError("Invalid WA SOC text encoding") from exc
    if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", text):
        raise ValueError("Invalid WA SOC control character")
    lines = text.splitlines()
    if not lines:
        raise ValueError("WA SOC document requires a nonempty title heading")
    title, _ = source_heading(payload)
    sections = []
    name = None
    body = []
    for line in lines[1:]:
        if line.startswith(("## ", "# ")):
            if (
                line.startswith("# ")
                and source_heading(line.encode("utf-8"))[1] is not None
            ):
                raise ValueError("Multiple WA SOC advisory identities")
            if name is not None:
                sections.append((name, "\n".join(body).strip()))
            elif any(v.strip() for v in body):
                sections.append(("", "\n".join(body).strip()))
            name, body = line.lstrip("#").strip(), []
            if not name:
                raise ValueError("Empty WA SOC section heading")
        else:
            body.append(line)
    if name is not None or any(v.strip() for v in body):
        sections.append((name or "", "\n".join(body).strip()))
    if not sections:
        raise ValueError("WA SOC advisory body is empty")
    cves = tuple(dict.fromkeys(CVE_REFERENCE.findall(text)))
    assert all(CVE_PATTERN.fullmatch(cve) for cve in cves)
    return WasocNotice(advisory_id, title, cves, tuple(sections), payload)
