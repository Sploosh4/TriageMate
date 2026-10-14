"""Microsoft Windows CNA status evaluation; no generic custom-version ordering.

CVE schema status/default/change semantics:
https://github.com/CVEProject/cve-schema/blob/main/schema/CVE_Record_Format.json
Conflicting overlapping assertions remain unknown instead of choosing precedence.
"""

from standalone.evidence_pipeline.assessment.windows_version_match import (
    evaluate_criterion,
    windows_build,
)
from standalone.evidence_pipeline.assessment.windows_cpe_match import (
    evaluate_configurations,
)

_STATUSES = ("affected", "unaffected", "unknown")


def evaluate_record(source_fields, *, provider, facts):
    """Reconcile product and CPE assertions without choosing source precedence."""
    if not isinstance(source_fields, dict):
        return dict(state="unknown", reason="invalid_cna_record", entries=[])
    product = evaluate_products(
        source_fields.get("affected"), provider=provider, facts=facts
    )
    if "configurations" in source_fields:
        return dict(
            state="unknown",
            reason="textual_configuration_requires_evidence",
            product=product,
        )
    if "cpeApplicability" not in source_fields:
        return product
    cpe = evaluate_configurations(source_fields["cpeApplicability"], facts=facts)
    state = "unknown"
    reason = "incomplete_product_or_cpe_evidence"
    if product["state"] in ("affected", "unaffected") and cpe["state"] != "unknown":
        if (product["state"] == "affected") == (cpe["state"] == "matched"):
            state = product["state"]
            reason = "consistent_product_and_cpe_evidence"
        else:
            reason = "conflicting_product_and_cpe_evidence"
    return dict(state=state, reason=reason, product=product, cpe=cpe)


def _status_for_versions(entry, candidate):
    default = entry.get("defaultStatus", "unknown")
    if default not in _STATUSES:
        return None, "invalid_default_status"
    versions = entry.get("versions", [])
    if not isinstance(versions, list) or (
        not versions and ("versions" in entry or "defaultStatus" not in entry)
    ):
        return None, "missing_version_status"
    matches = []
    for index, item in enumerate(versions):
        if not isinstance(item, dict) or set(item) - {
            "version",
            "status",
            "versionType",
            "lessThan",
            "lessThanOrEqual",
            "changes",
        }:
            return None, "unsupported_version_fields"
        status = item.get("status")
        start = windows_build(item.get("version"))
        if (
            status not in _STATUSES
            or start is None
            or item.get("versionType", "custom") != "custom"
        ):
            return None, "unsupported_windows_version_or_status"
        bounds = [key for key in ("lessThan", "lessThanOrEqual") if key in item]
        if len(bounds) > 1:
            return None, "conflicting_version_bounds"
        changes = item.get("changes", [])
        if not bounds:
            if "changes" in item:
                return None, "changes_require_range"
            if candidate == start:
                matches.append((status, index))
            continue
        if item.get("versionType") != "custom":
            return None, "range_requires_windows_version_type"
        end = windows_build(item[bounds[0]]) if item[bounds[0]] != "*" else None
        if (end is None and item[bounds[0]] != "*") or (
            end is not None
            and (end < start or (end == start and bounds[0] == "lessThan"))
        ):
            return None, "invalid_version_range"
        if not isinstance(changes, list):
            return None, "invalid_status_changes"
        ordered = {}
        for change in changes:
            if not isinstance(change, dict) or set(change) != {"at", "status"}:
                return None, "invalid_status_change"
            at = windows_build(change["at"])
            changed = change["status"]
            if (
                at is None
                or changed not in _STATUSES
                or at < start
                or (
                    end is not None
                    and (at > end or (at == end and bounds[0] == "lessThan"))
                )
            ):
                return None, "status_change_outside_range"
            if at in ordered and ordered[at] != changed:
                return None, "conflicting_status_changes"
            ordered[at] = changed
        inside = candidate >= start and (
            end is None
            or candidate < end
            or (bounds[0] == "lessThanOrEqual" and candidate == end)
        )
        if inside:
            for at, changed in sorted(ordered.items()):
                if at <= candidate:
                    status = changed
            matches.append((status, index))
    statuses = {status for status, _ in matches}
    if len(statuses) > 1:
        return None, "conflicting_matching_version_statuses"
    if matches:
        return (
            matches[0][0],
            [index for _, index in matches],
        ), "explicit_version_status"
    return (
        (default, []),
        "publisher_default_status"
        if "defaultStatus" in entry
        else "outside_ranges_default_unknown",
    )


def evaluate_products(affected, *, provider, facts):
    """Evaluate matching Microsoft CNA product entries against pinned facts.

    Returns entry/version indexes so callers can expose the original statements.
    Caller must supply published CNA content and pin facts to the finding receipt;
    this function does not accept display-name guesses or infer patch installation.
    """

    def unknown(reason, entries=None):
        return dict(state="unknown", reason=reason, entries=entries or [])

    if not isinstance(provider, str) or provider.casefold() != "microsoft":
        return unknown("unsupported_publisher")
    if not isinstance(affected, list) or not isinstance(facts, dict):
        return unknown("invalid_product_evidence")
    expected_keys = {
        "product",
        "publisher",
        "version",
        "operating_system",
        "release",
        "os_build",
        "os_architecture",
        "os_processor",
    }
    if set(facts) != expected_keys:
        return unknown("incomplete_pinned_facts")
    # Reuse the identity/build/architecture checks without claiming a source CPE.
    selector = (
        f"cpe:2.3:o:microsoft:{facts['product']}_{facts['release']}:*:*:*:*:*:*:*:*"
    )
    identity = evaluate_criterion({"criteria": selector, "vulnerable": True}, **facts)
    if identity["state"] != "matched":
        return unknown(identity["reason"])
    expected = f"Windows {facts['product'].split('_')[1]} Version {facts['release']}"
    platform = {
        "x64": "x64-based Systems",
        "ARM64": "ARM64-based Systems",
        "arm64": "ARM64-based Systems",
        "x86": "32-bit Systems",
    }[facts["os_processor"]]
    results = []
    for index, entry in enumerate(affected):
        if not isinstance(entry, dict):
            return unknown("invalid_product_entry")
        if not isinstance(entry.get("vendor"), str) or not isinstance(
            entry.get("product"), str
        ):
            return unknown("invalid_product_identity")
        if (
            entry.get("vendor") != "Microsoft"
            or not isinstance(entry.get("product"), str)
            or entry["product"].casefold() != expected.casefold()
        ):
            continue
        if set(entry) - {"vendor", "product", "platforms", "versions", "defaultStatus"}:
            return unknown("unsupported_product_constraints")
        platforms = entry.get("platforms")
        if (
            not isinstance(platforms, list)
            or not platforms
            or any(
                p not in ("x64-based Systems", "ARM64-based Systems", "32-bit Systems")
                for p in platforms
            )
        ):
            return unknown("missing_or_unsupported_platforms")
        if platform not in platforms:
            continue
        value, reason = _status_for_versions(entry, windows_build(facts["version"]))
        if value is None:
            return unknown(reason, results)
        status, version_indexes = value
        results.append(
            dict(
                product_index=index,
                version_indexes=version_indexes,
                state=status,
                reason=reason,
            )
        )
    if not results:
        return unknown("no_supported_product_platform_entry")
    statuses = {row["state"] for row in results}
    if len(statuses) != 1:
        return unknown("conflicting_product_statuses", results)
    return dict(
        state=results[0]["state"],
        reason="evaluated_microsoft_windows_cna",
        entries=results,
    )
