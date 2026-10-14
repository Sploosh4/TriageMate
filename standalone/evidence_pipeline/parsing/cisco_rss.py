"""Publisher-advertised Cisco CSAF RSS routes; no arbitrary link fetching.

https://sec.cloudapps.cisco.com/security/center/rss.x?i=44 advertises this feed.
Mixed-case native IDs and raw publisher dates survive; timezone is not invented.
"""

from dataclasses import dataclass
import re
from urllib.parse import urlsplit
from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException

from standalone.evidence_pipeline.contracts import SourceScope

FEED_URL = "https://sec.cloudapps.cisco.com/security/center/csaf_10.xml"
BASE = "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/"
ID = re.compile(r"cisco-sa-[A-Za-z0-9][A-Za-z0-9_.-]{0,240}\Z")
RSS = "{https://purl.org/rss/1.0/}"
DC = "{https://purl.org/dc/elements/1.1/}"
RDF = "{https://www.w3.org/1999/02/22-rdf-syntax-ns#}"


def endpoint(advisory_id):
    if not isinstance(advisory_id, str) or ID.fullmatch(advisory_id) is None:
        raise ValueError("Invalid Cisco advisory identity")
    return BASE + advisory_id + "/csaf/" + advisory_id + ".json"


def validate_scope(scope):
    """Bind a collection to one canonical publisher document before fetching."""
    if (
        not isinstance(scope, SourceScope)
        or (scope.source, scope.input_kind) != ("Cisco", "advisories")
        or scope.origin not in {"public", "synthetic"}
        or scope.tenant_id is not None
        or not scope.scope_reference.startswith(BASE)
    ):
        raise ValueError("Cisco requires its non-tenant publisher document scope")
    identity = scope.scope_reference[len(BASE) :].split("/", 1)[0]
    if endpoint(identity) != scope.scope_reference:
        raise ValueError("Invalid canonical Cisco advisory route")
    return identity


@dataclass(frozen=True)
class RssAdvisory:
    advisory_id: str
    url: str
    publisher_date_text: str | None
    source_link: str


def parse_feed(payload):
    try:
        root = ElementTree.fromstring(payload)
    except (ElementTree.ParseError, DefusedXmlException, TypeError) as exc:
        raise ValueError("Invalid Cisco RSS XML") from exc
    if root.tag != RDF + "RDF":
        raise ValueError("Unsupported Cisco RSS envelope")
    results = []
    seen = set()
    for item in root.findall(RSS + "item"):

        def value(tag):
            nodes = item.findall(tag)
            if len(nodes) > 1:
                raise ValueError("Duplicate Cisco RSS field")
            return nodes[0].text.strip() if nodes and nodes[0].text else None

        identity = value(RSS + "title")
        expected = endpoint(identity)
        link = value(RSS + "link")
        parsed = urlsplit(link or "")
        if (
            parsed.scheme not in {"http", "https"}
            or parsed.hostname != "sec.cloudapps.cisco.com"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port
            not in ({None, 80} if parsed.scheme == "http" else {None, 443})
            or parsed.fragment
            or parsed.path != urlsplit(expected).path
        ):
            raise ValueError("Cisco RSS link differs from fixed advisory route")
        # The publisher currently emits HTTP links with marketing query strings.
        # Fetch only the corresponding fixed HTTPS document URL, retaining its link.
        if identity in seen:
            raise ValueError("Duplicate Cisco RSS advisory")
        seen.add(identity)
        results.append(RssAdvisory(identity, expected, value(DC + "date"), link))
    if not results:
        raise ValueError("Cisco RSS contains no advisory items")
    return tuple(results)
