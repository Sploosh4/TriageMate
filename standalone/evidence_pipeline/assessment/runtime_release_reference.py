"""Validate publisher release correspondences without guessing version encodings.

This module consumes a retained public reference, never the network. Only explicit
stable release/MSIX/NuGet rows for the supplied runtime families are admitted.
Conflicting correspondences are refused rather than choosing a preferred row.
"""

import re

_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){1,3}")
_SUPPORTED = frozenset({"1.5", "1.6", "1.7", "1.8"})


def parse_reference(text: str) -> tuple[dict[str, str], ...]:
    """Read the publisher's Markdown table by column names, not line positions."""
    if not isinstance(text, str):
        raise ValueError("Runtime reference must be text")
    columns = None
    records = {}
    for line in text.splitlines():
        if not line.lstrip().startswith("|"):
            columns = None
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        lowered = [cell.casefold() for cell in cells]
        if (
            "release" in lowered
            and "nuget version" in lowered
            and "msix version" in lowered
        ):
            if any(
                lowered.count(name) != 1
                for name in ("release", "nuget version", "msix version")
            ):
                raise ValueError("Ambiguous runtime reference columns")
            columns = {
                name: lowered.index(name)
                for name in ("release", "nuget version", "msix version")
            }
            continue
        if columns is None:
            continue
        if all(re.fullmatch(r":?-+:?", cell) for cell in cells):
            continue
        if len(cells) <= max(columns.values()):
            raise ValueError("Incomplete runtime reference row")
        release, nuget, msix = (
            cells[columns[name]]
            for name in ("release", "nuget version", "msix version")
        )
        # Preview/experimental rows are not stable correspondence claims.
        if _VERSION.fullmatch(release) is None:
            continue
        family = ".".join(release.split(".")[:2])
        if family not in _SUPPORTED:
            continue
        if (
            len(release.split(".")) != 3
            or _VERSION.fullmatch(nuget) is None
            or _VERSION.fullmatch(msix) is None
            or len(msix.split(".")) != 4
        ):
            raise ValueError("Unsupported stable runtime correspondence")
        if ".".join(nuget.split(".")[:2]) != family:
            raise ValueError("Conflicting runtime release and NuGet family")
        record = dict(
            product="Microsoft.WindowsAppRuntime." + family,
            msix_version=msix,
            sdk_release=release,
            nuget_version=nuget,
        )
        key = (record["product"], msix)
        if key in records and records[key] != record:
            raise ValueError("Conflicting runtime release correspondences")
        records[key] = record
    if not records:
        raise ValueError("No supported runtime correspondences")
    return tuple(records[key] for key in sorted(records))
