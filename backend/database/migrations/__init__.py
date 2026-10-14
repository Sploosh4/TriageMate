"""Ordered revisions introduced after the consolidated baseline only.

A revision ships immutable SQL and independently constructed post-change catalogue
contracts. There are no supported pre-baseline upgrade paths in this registry.
"""

from dataclasses import dataclass
from pathlib import Path
import re


@dataclass(frozen=True)
class Migration:
    version: str
    source: Path
    contracts: tuple[Path, ...]
    retained_runner_contracts: tuple[Path, ...] = ()


MIGRATIONS: tuple[Migration, ...] = ()


def revisions() -> tuple[Migration, ...]:
    """Validate the checked-in order; never discover scripts from directory order."""
    seen = {"triagemate-baseline-v1"}
    for migration in MIGRATIONS:
        if (
            not re.fullmatch(r"[a-z][a-z0-9-]{1,95}", migration.version)
            or migration.version in seen
        ):
            raise ValueError("Migration versions must be unique explicit identifiers")
        contracts = (*migration.contracts, *migration.retained_runner_contracts)
        if not migration.contracts or len(set(contracts)) != len(contracts):
            raise ValueError("Each revision requires distinct trusted schema contracts")
        seen.add(migration.version)
    return MIGRATIONS
