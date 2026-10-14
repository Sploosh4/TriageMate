"""Combined completion proof for initial enrichment and recurring refresh."""

from dataclasses import dataclass, field
from pathlib import Path

from .enrichment_batch import ScheduledEnrichment
from .enrichment_refresh_selection import RefreshSelection
from . import enrichment_refresh_worker


@dataclass(frozen=True)
class RefreshingEnrichment(ScheduledEnrichment):
    bundle_root: Path = field(kw_only=True)

    def __post_init__(self):
        super().__post_init__()
        if not isinstance(self.bundle_root, Path) or not self.bundle_root.is_absolute():
            raise ValueError("Refresh proof requires an absolute bundle root")

    def refresh(self):
        return RefreshSelection(self)

    def committed(self, cursor, key, job):
        if not super().committed(cursor, key, job):
            return False
        try:
            initial = self.saved(cursor, key, job)
            refreshed = self.refresh().saved(cursor, key, job)
            if (
                initial is None
                or refreshed is None
                or len(initial) + len(refreshed) > self.limit
            ):
                return False
            return enrichment_refresh_worker.committed(
                cursor, self.refresh(), job, key, self.bundle_root
            )
        except (ValueError, OSError):
            return False
