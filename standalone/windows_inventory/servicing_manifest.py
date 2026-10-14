"""Read decoded Windows servicing XML without resolving paths or executing it.

Compressed-manifest decoding and active-package/hardlink attribution are separate
collection stages. An assembly declaration is not a file-integrity, CVE, installed
package, servicing-completion or Defender-assessment claim.
"""

import hashlib
import re

from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException

from standalone.evidence_pipeline.assessment.windows_version_match import windows_build


NAMESPACE = "urn:schemas-microsoft-com:asm.v3"


def _tag(name):
    return "{" + NAMESPACE + "}" + name


def _identity(element):
    attributes = dict(element.attrib)
    required = (
        "name",
        "version",
        "processorArchitecture",
        "publicKeyToken",
        "language",
    )
    if any(not attributes.get(key) for key in required):
        raise ValueError("Incomplete assembly identity")
    if windows_build(attributes["version"]) is None:
        raise ValueError("Unsupported assembly version")
    return attributes


def read_manifest(raw, *, expected_sha256):
    """Return exact declared identities/files/dependencies from verified XML bytes.

    The expected hash refers to decoded bytes, not the compressed source. Callers
    retain both hashes and the decoder/dictionary provenance. Paths stay literal;
    macro expansion or selecting files by basename would lose source identity.
    """
    if (
        not isinstance(raw, bytes)
        or not isinstance(expected_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None
    ):
        raise ValueError("Decoded bytes and expected SHA-256 required")
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("Decoded manifest hash mismatch")
    try:
        root = ElementTree.fromstring(
            raw, forbid_dtd=True, forbid_entities=True, forbid_external=True
        )
    except (ElementTree.ParseError, DefusedXmlException) as exc:
        raise ValueError("Invalid or unsafe servicing XML") from exc
    if root.tag != _tag("assembly") or root.get("manifestVersion") != "1.0":
        raise ValueError("Unsupported servicing manifest root")
    identities = root.findall(_tag("assemblyIdentity"))
    if len(identities) != 1:
        raise ValueError("Exactly one root assembly identity required")
    identity = _identity(identities[0])
    files = []
    for node in root.findall(_tag("file")):
        if not node.get("name"):
            raise ValueError("File declaration lacks a name")
        files.append(dict(node.attrib))
    # Parent/applicability identities are not dependency declarations.
    dependencies = []
    for dependency in root.findall(_tag("dependency")):
        for dependent in dependency.findall(_tag("dependentAssembly")):
            children = dependent.findall(_tag("assemblyIdentity"))
            if len(children) != 1:
                raise ValueError("Ambiguous dependent assembly")
            dependencies.append(
                {
                    "dependency": dict(dependency.attrib),
                    "dependent_assembly": dict(dependent.attrib),
                    "identity": _identity(children[0]),
                }
            )
    return {
        "decoded_sha256": expected_sha256,
        "assembly": identity,
        "declared_files": files,
        "declared_dependencies": dependencies,
        "scope": "decoded_servicing_declarations_only",
    }
