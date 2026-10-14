"""Offline, dated Windows OS evidence; no network, device mutation or patch choice.

An import retains original UTF-8 documents and request receipts. Registration,
native OS facts and per-device/version inventory must agree before a Defender
identity is selected. Unversioned software weakness totals are deliberately unused.
"""

from datetime import datetime, timedelta, timezone
from decimal import Decimal, ROUND_HALF_EVEN
import hashlib
import json
import re

CONTRACT = "triagemate-windows-os-evidence-v1"
MAX_BYTES = 32 * 1024 * 1024
LABELS = {
    "devices": "/api/machines",
    "software-inventory": "/api/machines/SoftwareInventoryByMachine",
    "vulnerabilities": "/api/machines/SoftwareVulnerabilitiesByMachine",
    "current-missing-kbs": None,
}
API = "https://api.security.microsoft.com"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def document(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result

    return json.loads(
        raw,
        object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite JSON")),
    )


def instant(value):
    if not isinstance(value, str):
        raise ValueError("Missing observation timestamp")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("Observation timestamps require a timezone")
    # Native PowerShell timestamps can have 100 ns precision. PostgreSQL rounds
    # to microseconds; Python truncates. Use the database precision consistently
    # while preserving the full original timestamp in the retained source bytes.
    fraction = re.search(r"\.(\d{7,})(?=Z|[+-])", value)
    if fraction:
        microseconds = (Decimal("0." + fraction[1]) * 1_000_000).quantize(
            Decimal(1), rounding=ROUND_HALF_EVEN
        )
        result += timedelta(microseconds=int(microseconds) - result.microsecond)
    return result.astimezone(timezone.utc)


def native(value, binding):
    if any(
        value.get(k) != getattr(binding, attr)
        for k, attr in (
            ("tenant_id", "tenant_id"),
            ("device_id", "device_id"),
            ("machine_guid", "machine_guid"),
        )
    ):
        raise ValueError("Native evidence differs from the independently bound device")
    if (value.get("release"), str(value.get("build"))) not in {
        ("24H2", "26100"),
        ("25H2", "26200"),
    } or value.get("architecture") != "AMD64":
        raise ValueError(
            "Only explicitly identified Windows 11 24H2/25H2 x64 is supported"
        )
    if type(value.get("ubr")) is not int or value["ubr"] < 0:
        raise ValueError("Invalid Windows build revision")
    instant(value.get("observed_at"))
    return f"10.0.{value['build']}.{value['ubr']}"


def evaluate(raw, *, binding, origin):
    """Validate complete retained exports and return a conservative interpretation.

    The 24-hour compatibility window bounds association of separately observed
    facts; it is not a freshness SLA or proof of unchanged intervening state.
    """
    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
        raise ValueError("OS evidence exceeds the bounded import contract")
    bundle = document(raw)
    if (
        bundle.get("contract") != CONTRACT
        or bundle.get("origin") != origin
        or origin not in {"lab", "synthetic"}
    ):
        raise ValueError("OS evidence contract or origin mismatch")
    if bundle.get("collection_tenant_id") != binding.tenant_id:
        raise ValueError("Retained collector tenant binding is required")
    sources = bundle.get("sources")
    if (
        not isinstance(sources, dict)
        or not {"native", "installed", "requests"} <= sources.keys()
    ):
        raise ValueError("Required retained source documents are missing")
    decoded, references = {}, {}
    for name, source in sources.items():
        if not isinstance(source, dict) or not isinstance(source.get("text"), str):
            raise ValueError("Sources must retain original UTF-8 text")
        digest = hashlib.sha256(source["text"].encode()).hexdigest()
        if digest != source.get("sha256"):
            raise ValueError("Retained source hash mismatch")
        decoded[name] = document(source["text"])
        references[name] = {"sha256": digest}
    identity = decoded["native"]
    version = native(identity, binding)
    installed = decoded["installed"]
    if native(installed.get("identity", {}), binding) != version:
        raise ValueError("Installed update evidence has a different Windows version")
    native_time = instant(identity["observed_at"])
    install_time = instant(installed.get("observed_at"))
    if abs(install_time - native_time) > timedelta(hours=24):
        raise ValueError(
            "Native and installed-update observations are incompatible in time"
        )
    queries = bundle.get("queried_kbs")
    if (
        not isinstance(queries, list)
        or not queries
        or len(set(queries)) != len(queries)
        or any(
            not isinstance(k, str) or not re.fullmatch(r"KB[0-9]{6,8}", k)
            for k in queries
        )
    ):
        raise ValueError("Declare the bounded native HotFix query scope")
    hotfixes = installed.get("rows")
    if not isinstance(hotfixes, list) or any(
        r.get("HotFixID") not in queries for r in hotfixes
    ):
        raise ValueError("Installed update rows differ from declared query scope")
    requests = decoded["requests"]
    if not isinstance(requests, list):
        raise ValueError("Missing request manifest")
    exports, windows = {}, []
    for label, route in LABELS.items():
        matches = [r for r in requests if r.get("label") == label]
        if len(matches) != 1 or matches[0].get("complete") is not True:
            raise ValueError("Required export is absent, duplicate or incomplete")
        receipt = matches[0]
        pages = receipt.get("pages")
        # This bounded adapter deliberately rejects pagination until an exact
        # continuation contract is implemented; it never silently drops pages.
        if not isinstance(pages, list) or len(pages) != 1:
            raise ValueError(
                "This offline adapter requires a single complete export page"
            )
        page = pages[0]
        name = label + "-0"
        payload = decoded.get(name)
        if (
            not isinstance(payload, dict)
            or not isinstance(payload.get("value"), list)
            or payload.get("@odata.nextLink")
            or payload.get("nextLink")
        ):
            raise ValueError("Export payload is missing or paginated")
        if (
            page.get("status") != 200
            or page.get("sha256") != references[name]["sha256"]
            or type(receipt.get("count")) is not int
            or receipt["count"] != len(payload["value"])
        ):
            raise ValueError("Export receipt, count or content hash differs")
        url = page.get("url", "")
        if route and url != API + route:
            raise ValueError("Unexpected retained Microsoft endpoint")
        if not route and not re.fullmatch(
            re.escape(API) + r"/api/machines/[a-f0-9]{40}/getmissingkbs", url
        ):
            raise ValueError("Missing-KB export lacks exact device endpoint")
        start, end = instant(page.get("started_at")), instant(page.get("finished_at"))
        if (
            end < start
            or end - start > timedelta(hours=1)
            or abs(end - native_time) > timedelta(hours=24)
        ):
            raise ValueError("Native and export observations are incompatible in time")
        windows.extend([start, end])
        references[name].update(
            url=url, started_at=start.isoformat(), finished_at=end.isoformat()
        )
        exports[label] = payload["value"]
    if max(windows) - min(windows) > timedelta(hours=1):
        raise ValueError("Exports do not form a bounded observation window")
    devices = exports["devices"]
    if len({d.get("id") for d in devices}) != len(devices) or any(
        not isinstance(d.get("id"), str) or not re.fullmatch(r"[a-f0-9]{40}", d["id"])
        for d in devices
    ):
        raise ValueError("Duplicate or invalid provider device identity")
    # Foreign registrations are refused, rather than broadening the lab scope.
    if any(
        d.get("aadDeviceId", "").lower() != binding.device_id.lower() for d in devices
    ):
        raise ValueError("Export includes a foreign registration")
    ids = {d["id"] for d in devices}
    for label in ("software-inventory", "vulnerabilities"):
        if any(r.get("deviceId") not in ids for r in exports[label]):
            raise ValueError("Export contains an unbound provider identity")
    provider_rows, matching = [], []
    for device in devices:
        software = [
            r
            for r in exports["software-inventory"]
            if r.get("deviceId") == device["id"]
            and r.get("softwareName") == "windows_11"
            and r.get("softwareVendor") == "microsoft"
        ]
        seen = instant(device.get("lastSeen"))
        first = instant(device.get("firstSeen"))
        if first > seen or seen > max(windows) + timedelta(minutes=2):
            raise ValueError("Provider observation timestamps are invalid")
        exact = (
            len(software) == 1
            and abs(seen - native_time) <= timedelta(hours=24)
            and software[0].get("softwareVersion") == version
            and device.get("osPlatform") == "Windows11"
            and str(device.get("osBuild")) == str(identity["build"])
            and device.get("version") == identity["release"]
            and device.get("osProcessor") == "x64"
            and device.get("osArchitecture") in ("64-bit", "x64")
            and not device.get("mergedIntoMachineId")
            and device.get("isPotentialDuplication") is not True
            and device.get("isExcluded") is not True
        )
        if exact:
            matching.append(device["id"])
        provider_rows.append(
            {
                "native_device_id": device["id"],
                "windows_versions": sorted(
                    {str(s.get("softwareVersion")) for s in software}
                ),
                "matches_native_os": exact,
                "first_seen": first.isoformat(),
                "last_seen": seen.isoformat(),
                "health_status": device.get("healthStatus"),
                "merged_into": device.get("mergedIntoMachineId"),
                "potential_duplicate": device.get("isPotentialDuplication"),
                "state": "unresolved",
            }
        )
    selected = matching[0] if len(matching) == 1 else None
    if selected:
        chosen = next(r for r in provider_rows if r["native_device_id"] == selected)
        # Do not choose by recency alone or hide competing contemporaneous records.
        if any(
            r["native_device_id"] != selected
            and (
                not r["windows_versions"]
                or version in r["windows_versions"]
                or instant(r["last_seen"]) >= instant(chosen["first_seen"])
            )
            for r in provider_rows
        ):
            selected = None
    for row in provider_rows:
        row["state"] = (
            "selected"
            if row["native_device_id"] == selected
            else ("historical_incompatible_os" if selected else "unresolved")
        )
    missing_id = references["current-missing-kbs-0"]["url"].split("/")[-2]
    if missing_id not in ids or any(
        r.get("machineId", missing_id) != missing_id
        for r in exports["current-missing-kbs"]
    ):
        raise ValueError("Missing-KB evidence has a different endpoint device")
    missing_ids = [r.get("id") for r in exports["current-missing-kbs"]]
    if any(
        not isinstance(k, str) or not re.fullmatch(r"(?:KB)?[0-9]{6,8}", k)
        for k in missing_ids
    ) or len(set(missing_ids)) != len(missing_ids):
        raise ValueError("Invalid or duplicate missing update identifier")
    if selected and missing_id != selected:
        raise ValueError("Missing-KB evidence belongs to another provider identity")
    observed = []
    for row in hotfixes:
        if row["HotFixID"] not in {r["kb"] for r in observed}:
            observed.append(
                {
                    "kb": row["HotFixID"],
                    "description": row.get("Description"),
                    "installed_on": row.get("InstalledOn"),
                    "observed_at": install_time.isoformat(),
                }
            )
    windows_findings = [
        r
        for r in exports["vulnerabilities"]
        if r.get("deviceId") == selected and r.get("softwareName") == "windows_11"
    ]
    if any(
        r.get("softwareVersion") != version or r.get("softwareVendor") != "microsoft"
        for r in windows_findings
    ):
        raise ValueError(
            "Selected Windows findings have incompatible product/version facts"
        )
    missing_rows = exports["current-missing-kbs"] if selected else None
    return {
        "contract": CONTRACT,
        "origin": origin,
        "binding": {
            "tenant_id": binding.tenant_id,
            "device_id": binding.device_id,
            "machine_guid": binding.machine_guid,
        },
        "native_observed_at": native_time.isoformat(),
        "windows_version": version,
        "release": identity["release"],
        "architecture": "x64",
        "product_label": f"Windows 11 Version {identity['release']} for x64-based Systems",
        "provider_observed_at": max(windows).isoformat(),
        "providers": provider_rows,
        "selected_native_device_id": selected,
        "identity_state": "selected_from_compatible_retained_evidence"
        if selected
        else "unresolved",
        "installed_updates": observed,
        "queried_kbs": queries,
        "missing_updates": missing_rows,
        "windows_findings": windows_findings if selected else None,
        "device_findings": [
            r for r in exports["vulnerabilities"] if r.get("deviceId") == selected
        ]
        if selected
        else None,
        "missing_state": ("none_reported" if not missing_rows else "reported_missing")
        if selected
        else "identity_unresolved",
        "sources": references,
        "limits": "Dated retained evidence; separate observation times; no complete Windows Update scan or exhaustive installed-update inventory; no fully-patched assertion.",
    }
