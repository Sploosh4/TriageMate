"""MITRE Enterprise ATT&CK STIX definitions; never inferred CVE mappings."""

from dataclasses import dataclass
import re
from uuid import UUID

from standalone.evidence_pipeline.contracts import SourceScope
from standalone.evidence_pipeline.parsing.osv import timestamp
from standalone.evidence_pipeline.parsing.public_inputs import PublicFeed, _json, _text

URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"


@dataclass(frozen=True)
class TechniqueRecord:
    source_record_id: str
    technique_ids: tuple[str, ...]
    raw: dict

    @property
    def cve_ids(self):
        return ()


@dataclass(frozen=True)
class AttackFeed(PublicFeed):
    records: tuple[TechniqueRecord, ...]
    metadata: dict


def stix_id(value, kind):
    if not isinstance(value, str) or not value.startswith(kind + "--"):
        raise ValueError("Invalid ATT&CK STIX identity")
    suffix = value[len(kind) + 2 :]
    if str(UUID(suffix)) != suffix:
        raise ValueError("Noncanonical ATT&CK STIX identity")
    return value


def parse_attack(payload, *, scope):
    if (
        not isinstance(scope, SourceScope)
        or (scope.source, scope.input_kind)
        != ("MITRE ATT&CK", "enterprise_definitions")
        or scope.tenant_id is not None
        or scope.origin not in {"public", "synthetic"}
        or scope.scope_reference != URL
    ):
        raise ValueError("ATT&CK requires its fixed Enterprise definition scope")
    if not isinstance(payload, bytes) or not payload:
        raise ValueError("Invalid ATT&CK bundle size")
    document = _json(payload.decode("utf-8-sig"))
    if document.get("type") != "bundle" or not isinstance(
        document.get("objects"), list
    ):
        raise ValueError("ATT&CK requires a STIX bundle")
    stix_id(document.get("id"), "bundle")
    records = []
    seen = set()
    collections = []
    for obj in document["objects"]:
        if not isinstance(obj, dict):
            raise ValueError("Invalid ATT&CK bundle object")
        if obj.get("type") == "x-mitre-collection":
            collections.append(
                {key: value for key, value in obj.items() if key != "x_mitre_contents"}
            )
        if obj.get("type") != "attack-pattern":
            continue
        identity = stix_id(obj.get("id"), "attack-pattern")
        modified = timestamp(obj.get("modified"))
        timestamp(obj.get("created"))
        _text(obj.get("name"))
        if obj.get("spec_version") != "2.1":
            raise ValueError("ATT&CK definition requires STIX 2.1")
        for flag in ("revoked", "x_mitre_deprecated", "x_mitre_is_subtechnique"):
            if flag in obj and type(obj[flag]) is not bool:
                raise ValueError("Invalid ATT&CK source flag")
        refs = obj.get("external_references", [])
        if not isinstance(refs, list):
            raise ValueError("Invalid ATT&CK external references")
        techniques = []
        for ref in refs:
            if not isinstance(ref, dict):
                raise ValueError("Invalid ATT&CK external reference")
            if ref.get("source_name") == "mitre-attack":
                code = ref.get("external_id")
                if not isinstance(code, str) or not re.fullmatch(
                    r"T[0-9]{4}(?:\.[0-9]{3})?", code
                ):
                    raise ValueError("Invalid explicit ATT&CK technique ID")
                if code not in techniques:
                    techniques.append(code)
        if (identity, modified) in seen:
            raise ValueError("Repeated ATT&CK object version")
        seen.add((identity, modified))
        records.append(TechniqueRecord(identity, tuple(techniques), obj))
    metadata = {key: value for key, value in document.items() if key != "objects"}
    metadata["collections"] = collections
    return AttackFeed(scope, payload, tuple(records), metadata)
