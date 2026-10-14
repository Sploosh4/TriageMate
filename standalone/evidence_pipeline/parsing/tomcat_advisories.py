"""Parse Apache's website-source notices; ranges and fix prose remain source text.

Contract: apache/tomcat-site, xdocs/security-{9,10,11}.xml on trunk.
This parser does not enable transport or infer installed-software applicability.
"""

from dataclasses import dataclass
import re
from xml.etree.ElementTree import ParseError, tostring

from defusedxml.ElementTree import fromstring
from defusedxml.common import DefusedXmlException

from standalone.evidence_pipeline.parsing.public_inputs import CVE_PATTERN

BASE = "https://raw.githubusercontent.com/apache/tomcat-site/trunk/xdocs/"
MAX_ELEMENTS = 100_000


@dataclass(frozen=True)
class TomcatNotice:
    cve_id: str
    section: str
    section_date: str | None
    section_context: tuple[str, ...]
    fixed_release: str | None
    title: str
    paragraphs: tuple[str, ...]
    affected_text: tuple[str, ...]
    related_cves: tuple[str, ...]
    commit_references: tuple[str, ...]
    source_xml: str


def text(element):
    return " ".join("".join(element.itertext()).split())


def parse_tomcat(payload, *, series):
    if series not in ("9", "10", "11"):
        raise ValueError("Unsupported Tomcat series")
    if not isinstance(payload, bytes) or not payload:
        raise ValueError("Tomcat XML requires bounded immutable bytes")
    try:
        root = fromstring(
            payload, forbid_dtd=True, forbid_entities=True, forbid_external=True
        )
    except (ParseError, DefusedXmlException) as exc:
        raise ValueError("Invalid or unsafe Tomcat XML") from exc
    if root.tag != "document" or root.find("body") is None:
        raise ValueError("Unsupported Tomcat document")
    if sum(1 for _ in root.iter()) > MAX_ELEMENTS:
        raise ValueError("Tomcat element limit exceeded")
    title = root.find("properties/title")
    if title is None or text(title) != f"Apache Tomcat {series} vulnerabilities":
        raise ValueError("Tomcat document series differs")
    notices = []
    for section in root.findall("body/section"):
        name = section.get("name", "")
        fixed = re.fullmatch(
            r"Fixed in Apache Tomcat ([0-9]+\.[0-9]+\.[0-9]+(?:-M[0-9]+)?)", name
        )
        if fixed and not fixed[1].startswith(series + "."):
            raise ValueError("Tomcat fixed release belongs to another series")
        header, content = None, []
        context = []

        def finish():
            if header is None:
                return
            native, heading = header
            paragraphs = tuple(text(item) for item in content)
            related = tuple(
                dict.fromkeys(
                    text(cve)
                    for item in content
                    for cve in item.iter("cve")
                    if text(cve) != native
                )
            )
            if any(not CVE_PATTERN.fullmatch(value) for value in related):
                raise ValueError("Invalid related Tomcat CVE")
            notices.append(
                TomcatNotice(
                    native,
                    name,
                    section.get("rtext"),
                    tuple(context),
                    fixed[1] if fixed else None,
                    heading,
                    paragraphs,
                    tuple(
                        value for value in paragraphs if value.startswith("Affects:")
                    ),
                    related,
                    tuple(
                        dict.fromkeys(
                            item.get("hash", "")
                            for part in content
                            for item in part.iter("hashlink")
                        )
                    ),
                    "".join(tostring(item, encoding="unicode") for item in content),
                )
            )

        for item in section:
            cves = item.findall("cve")
            strong = item.find("strong")
            if item.tag == "p" and strong is not None and cves:
                finish()
                if len(cves) != 1 or not CVE_PATTERN.fullmatch(text(cves[0])):
                    raise ValueError("Ambiguous Tomcat notice identity")
                header, content = (text(cves[0]), text(strong)), []
            if header is not None:
                content.append(item)
            else:
                context.append(text(item))
        finish()
    if not notices:
        raise ValueError("No recognized Tomcat notices; investigate source layout")
    return tuple(notices)
