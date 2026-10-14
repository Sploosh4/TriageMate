"""Read-only file adapter for the native and selected-component evidence contracts."""

import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import stat

from .component_check import (
    AssemblyIdentity,
    AssemblyObservation,
    CheckContext,
    ComponentIdentity,
    ComponentRule,
    SourceAnchor,
    check_inventory,
    check_selected_components,
)
from .contract import DeviceBinding


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate evidence field")
        value[key] = item
    return value


def _constant(value):
    raise ValueError("Nonfinite evidence value")


def load(path):
    return json.loads(
        read_regular(path), object_pairs_hook=_unique, parse_constant=_constant
    )


def read_regular(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("Regular evidence file required")
        return stream.read()


def evaluate_files(*, inventory, binding, evidence, sources):
    """No external requests or database writes; original files remain unchanged.

    The binding file is independently configured, not derived from inventory.
    Sources are content-addressed files named by SHA-256 directly under sources.
    Source hashes protect integrity, not the correctness of reviewed rule meanings.
    """
    expected = DeviceBinding(**load(binding))
    data = load(evidence)
    if (
        set(data) != {"contract", "context", "rules"}
        or data["contract"] != "triagemate-component-rules-v1"
    ):
        raise ValueError("Unsupported component evidence contract")
    fields = dict(data["context"])
    fields["binding"] = DeviceBinding(**fields["binding"])
    fields["observed_at"] = datetime.fromisoformat(fields["observed_at"])
    fields["source"] = SourceAnchor(**fields["source"])
    fields["conditions"] = tuple(tuple(p) for p in fields.get("conditions", []))
    assemblies = []
    for original in fields.get("assemblies", []):
        item = dict(original)
        item["identity"] = AssemblyIdentity(**item["identity"])
        item["observed_at"] = datetime.fromisoformat(item["observed_at"])
        item["source"] = SourceAnchor(**item["source"])
        assemblies.append(AssemblyObservation(**item))
    fields["assemblies"] = tuple(assemblies)
    context = CheckContext(**fields)
    rules = parse_rules(data["rules"])
    anchors = [context.source, *(a.source for a in assemblies)]
    for rule in rules:
        anchors.extend(
            (
                rule.identity_source,
                rule.vulnerability_source,
                rule.fix_source,
                rule.conditions_source,
            )
        )
    retained = read_sources(sources, anchors)
    return check_inventory(
        read_regular(inventory),
        binding=expected,
        context=context,
        rules=rules,
        retained_sources=retained,
    )


def parse_rules(values):
    rules = []
    for original in values:
        item = dict(original)
        item["component"] = ComponentIdentity(**item["component"])
        for key in (
            "identity_source",
            "vulnerability_source",
            "fix_source",
            "conditions_source",
        ):
            item[key] = SourceAnchor(**item[key])
        item["required_conditions"] = tuple(
            tuple(p) for p in item.get("required_conditions", [])
        )
        if item.get("assembly") is not None:
            item["assembly"] = AssemblyIdentity(**item["assembly"])
        rules.append(ComponentRule(**item))
    return rules


def read_sources(sources, anchors):
    root = Path(sources).resolve(strict=True)
    retained = {}
    for anchor in anchors:
        path = root / anchor.sha256
        if path.resolve(strict=True).parent != root or path.is_symlink():
            raise ValueError(
                "Source must be a direct nonsymlink content-addressed file"
            )
        retained[anchor.sha256] = read_regular(path)
    return retained


def selected_file_inputs(*, selected, binding, evidence, sources):
    """Use native selected-snapshot context, never a fabricated full inventory."""
    expected = DeviceBinding(**load(binding))
    data = load(evidence)
    if (
        set(data) != {"contract", "origin", "rules"}
        or data["contract"] != "triagemate-selected-component-rules-v1"
    ):
        raise ValueError("Unsupported selected-component evidence contract")
    rules = parse_rules(data["rules"])
    anchors = [
        anchor
        for rule in rules
        for anchor in (
            rule.identity_source,
            rule.vulnerability_source,
            rule.fix_source,
            rule.conditions_source,
        )
    ]
    return dict(
        raw=read_regular(selected),
        binding=expected,
        origin=data["origin"],
        rules=rules,
        retained_sources=read_sources(sources, anchors),
    )


def evaluate_selected_files(**paths):
    return check_selected_components(**selected_file_inputs(**paths))


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Offline independent Windows component checks"
    )
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--inventory")
    inputs.add_argument("--selected")
    for name in ("binding", "evidence", "sources"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args(argv)
    try:
        values = vars(args).copy()
        if values.pop("selected") is not None:
            values.pop("inventory")
            result = evaluate_selected_files(selected=args.selected, **values)
        else:
            result = evaluate_files(**values)
    except (ValueError, TypeError, KeyError, OSError, RecursionError):
        parser.exit(
            2,
            "Component evidence rejected; check contracts, identity, timestamps and source hashes.\n",
        )
    print(json.dumps(result, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
