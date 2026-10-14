"""Read-only comparison; source correspondence never proves absence of risk.

Callers retain original exports and supply an independently verified device binding.
The returned evidence can be displayed or retained as a diagnostic, not imported as
new vulnerability observations or used to close findings.
"""

from dataclasses import dataclass

from standalone.evidence_pipeline.contracts import identifier, utc


@dataclass(frozen=True)
class DeviceContext:
    origin: str
    tenant_id: str
    registration_id: str
    defender_device_id: str

    def __post_init__(self):
        if self.origin not in ("synthetic", "lab"):
            raise ValueError("Explicit synthetic or dedicated lab origin required")
        for field in ("tenant_id", "registration_id"):
            object.__setattr__(self, field, identifier(getattr(self, field)))
        if (
            not isinstance(self.defender_device_id, str)
            or not self.defender_device_id.strip()
        ):
            raise ValueError("Exact Defender device identity required")


def compare(
    *,
    local_context,
    export_context,
    local_version,
    local_observed_at,
    exported_at,
    assessed,
    unsupported,
    aliases,
    complete,
):
    """Compare only explicitly supported aliases within one exact device instance.

    Product aliases are exact (vendor, name) pairs supplied by the caller's
    evidence-backed mapping. Never derive them through fuzzy package matching.
    Version differences are literal, not necessarily proof of staleness: Microsoft
    may normalize versions. Collection time is never an assessment timestamp.
    """
    if not isinstance(local_context, DeviceContext) or local_context != export_context:
        raise ValueError("Evidence device, tenant, origin or registration differs")
    if complete is not True:
        raise ValueError("Complete assessed and unsupported exports required")
    local_time = utc(local_observed_at)
    collected = utc(exported_at)
    selected = {"assessed": [], "unsupported": []}
    for label, values in (("assessed", assessed), ("unsupported", unsupported)):
        for row in values:
            if row.get("deviceId") != export_context.defender_device_id:
                raise ValueError("Export row belongs to another device instance")
            for field in ("softwareVendor", "softwareName", "softwareVersion"):
                if not isinstance(row.get(field), str) or not row[field].strip():
                    raise ValueError("Incomplete Microsoft software identity")
            if (row["softwareVendor"], row["softwareName"]) in aliases:
                selected[label].append(dict(row))
    matching = {
        key: [r for r in values if r["softwareVersion"] == local_version]
        for key, values in selected.items()
    }
    if not isinstance(local_version, str) or not local_version.strip():
        state = "incomplete_local_identity"
    elif matching["assessed"] and matching["unsupported"]:
        state = "overlapping_source_representations"
    elif matching["assessed"]:
        state = "assessed_product_version_correspondence"
    elif matching["unsupported"]:
        state = "explicit_non_cpe_product_version_correspondence"
    elif any(selected.values()):
        state = "product_version_mismatch"
    else:
        state = "unmatched_not_unsupported"
    return dict(
        state=state,
        local_version=local_version,
        local_observed_at=local_time.isoformat(),
        exported_at=collected.isoformat(),
        export_predates_local_observation=collected < local_time,
        assessment_time=None,
        temporal_alignment="unverified_assessment_time",
        source_records=selected,
        vulnerability_coverage="unverified",
        limitations=[
            "Source collection and software first/last-seen times do not establish assessment time.",
            "A version difference may be stale evidence or version normalization; no finding transfers across it.",
            "An unmatched component is not explicitly unsupported; OS-level results do not prove component coverage.",
            "Assessed inventory correspondence and zero weaknesses do not prove all vulnerabilities are assessed or remediated.",
        ],
    )
