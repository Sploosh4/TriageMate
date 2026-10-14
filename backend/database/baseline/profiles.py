"""Exact installation profiles constructed independently from supported setup paths.

Profiles preserve ownership and effective authority; they are not inferred from
host names, database names or the presence of synthetic-looking evidence rows.
"""

from collections.abc import Mapping
import json
from pathlib import Path

BASE = Path(__file__).parent
PROFILES = ("empty", "synthetic", "runner")


def read_contract(
    profile: str = "empty", *, predecessor: bool = False
) -> dict[str, str]:
    if profile not in PROFILES:
        raise ValueError("Unknown database installation profile")
    folder = BASE if profile == "empty" else BASE / "profiles" / profile
    path = folder / (
        "predecessor-contract.json" if predecessor else "current-contract.json"
    )
    value = json.loads(path.read_text())
    if (
        not isinstance(value, dict)
        or not value
        or any(
            not isinstance(key, str) or not isinstance(digest, str) or len(digest) != 64
            for key, digest in value.items()
        )
    ):
        raise ValueError("Invalid checked-in schema contract")
    return dict(value)


def identify(actual: Mapping[str, str], *, predecessor: bool = False) -> str:
    matches = [
        profile
        for profile in PROFILES
        if actual == read_contract(profile, predecessor=predecessor)
    ]
    if len(matches) != 1:
        raise ValueError(
            "Database does not match exactly one supported installation profile"
        )
    return matches[0]


def identify_layout(actual: Mapping[str, str]) -> tuple[str, bool]:
    """Resolve exactly one independently verified profile and schema layout."""
    from .. import retained_runner

    matches = [
        (profile, predecessor)
        for profile in PROFILES
        for predecessor in (False, True)
        if actual == read_contract(profile, predecessor=predecessor)
    ]
    matches.extend(
        ("runner", predecessor)
        for predecessor in (False, True)
        if actual == retained_runner.contract(predecessor=predecessor)
    )
    if len(matches) != 1:
        raise ValueError("Database does not match exactly one supported profile/layout")
    return matches[0]
