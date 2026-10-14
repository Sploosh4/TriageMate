"""Select Catalog KB searches from explicitly pinned missing-patch snapshots.

This reads existing evidence only. It neither collects Microsoft data nor activates
Catalog requests. Scope/run bindings preserve the source-reported meaning; an
unusable patch reference must not silently become a successful empty selection.
"""

from dataclasses import dataclass
import re
from standalone.evidence_pipeline.parsing.catalog_discovery import KB
from standalone.evidence_pipeline.contracts import identifier


@dataclass(frozen=True)
class CatalogTargets:
    snapshots: tuple[tuple[str, str], ...]
    kbs: tuple[str, ...]
    unresolved_references: int

    @property
    def complete(self):
        return self.unresolved_references == 0


def select_targets(cursor, snapshots, *, origin, maximum=100):
    if origin not in {"synthetic", "lab"}:
        raise ValueError(
            "Missing-patch targets require explicit synthetic or lab origin"
        )
    if not isinstance(snapshots, dict) or not snapshots or len(snapshots) > 100:
        raise ValueError("Explicit bounded missing-patch snapshot bindings required")
    bindings = tuple(
        sorted((identifier(scope), identifier(run)) for scope, run in snapshots.items())
    )
    if type(maximum) is not int or not 1 <= maximum <= 1000:
        raise ValueError("Invalid Catalog target request budget")
    kbs, unresolved = set(), 0
    for scope, run in bindings:
        cursor.execute(
            "SELECT c.source_name,c.input_kind,a.complete,a.outcome,p.origin "
            "FROM evidence.collection_attempts a "
            "JOIN evidence.source_connections c ON c.id=a.connection_id "
            "JOIN evidence_pipeline.product_collection_coverage p ON p.connection_id=c.id "
            "WHERE a.connection_id=%s AND a.id=%s",
            (scope, run),
        )
        if cursor.fetchone() != (
            "Defender",
            "missing_patches",
            True,
            "success",
            origin,
        ):
            raise ValueError(
                "Target snapshot is incomplete, unauthorized or belongs to another scope"
            )
        cursor.execute(
            "SELECT DISTINCT p.source_patch_id FROM evidence.observation_receipts r "
            "JOIN evidence.device_missing_patches m ON m.receipt_id=r.id "
            "JOIN evidence.patches p ON p.id=m.patch_id AND p.receipt_id=r.id "
            "WHERE r.collection_attempt_id=%s ORDER BY p.source_patch_id",
            (run,),
        )
        for (reference,) in cursor:
            # Defender getmissingkbs documents numeric IDs (for example
            # "4540673") with a corresponding Catalog query "KB4540673".
            # This conversion is valid only after the source/input binding
            # above, and never rewrites the source patch or receipt.
            kb = (
                "KB" + reference
                if isinstance(reference, str)
                and re.fullmatch(r"[0-9]{4,10}", reference)
                else reference
            )
            if not isinstance(kb, str) or not KB.fullmatch(kb):
                unresolved += 1
                continue
            kbs.add(kb)
            if len(kbs) > maximum:
                raise ValueError(
                    "Catalog target request budget exceeded; selection is not complete"
                )
    return CatalogTargets(bindings, tuple(sorted(kbs)), unresolved)
