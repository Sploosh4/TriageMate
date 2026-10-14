"""Device-linked Defender advice, independent of public advisory recommendations."""

from dataclasses import dataclass

from standalone.evidence_pipeline.parsing.exposure import require_snapshot
from standalone.evidence_pipeline.parsing.update_status import required_text, count
from standalone.evidence_pipeline.parsing.devices import optional_text

TEXT_FIELDS = {
    "title": "recommendationName",
    "vendor": "vendor",
    "product_name": "productName",
    "recommended_version": "recommendedVersion",
    "recommended_program": "recommendedProgram",
    "recommended_vendor": "recommendedVendor",
    "category": "recommendationCategory",
    "subcategory": "subCategory",
    "remediation_type": "remediationType",
    "source_status": "status",
}
COUNT_FIELDS = ("weaknesses", "totalMachineCount", "exposedMachinesCount")
RETAINED_FIELDS = frozenset(("id",) + tuple(TEXT_FIELDS.values()) + COUNT_FIELDS)


@dataclass(frozen=True)
class Recommendation:
    source_id: str
    fields: tuple
    source_counts: tuple
    native_device_ids: tuple[str, ...]
    unbound_native_device_ids: tuple[str, ...]

    def observation(self):
        return dict(self.fields)


def normalize_recommendations(snapshot, associations, known_devices):
    require_snapshot(snapshot, "Defender", "recommendations")
    if not isinstance(associations, dict):
        raise ValueError("Recommendation associations must be an explicit mapping")
    seen = set()
    result = []
    for raw in snapshot.records():
        if set(raw) - RETAINED_FIELDS:
            raise ValueError("Unretained recommendation fields")
        source_id = required_text(raw.get("id"), "id")
        if source_id in seen or source_id not in associations:
            raise ValueError(
                "Duplicate recommendation or missing device association result"
            )
        seen.add(source_id)
        linked = associations[source_id]
        if (
            not isinstance(linked, list)
            or any(
                not isinstance(item, str) or not item.strip() or len(item) > 4000
                for item in linked
            )
            or len(linked) != len(set(linked))
        ):
            raise ValueError("Invalid recommendation device identifiers")
        fields = {
            key: optional_text(raw.get(field), field)
            for key, field in TEXT_FIELDS.items()
        }
        fields["title"] = required_text(
            raw.get("recommendationName"), "recommendationName"
        )
        counts = {key: count(raw.get(key), key) for key in COUNT_FIELDS}
        result.append(
            Recommendation(
                source_id,
                tuple(sorted(fields.items())),
                tuple(sorted(counts.items())),
                tuple(sorted(linked)),
                tuple(sorted(set(linked) - known_devices)),
            )
        )
    if set(associations) != seen:
        raise ValueError("Associations include an absent recommendation")
    return tuple(sorted(result, key=lambda item: item.source_id))
