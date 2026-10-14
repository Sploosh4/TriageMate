"""Reconcile retained native inventory with its authority and receipt hashes."""

from collections import Counter

from standalone.evidence_pipeline.persistence.attribution import digest, require, rows
from standalone.windows_inventory.contract import DeviceBinding, observation_key


def verify_windows_inventory(cur, sources, attempts, receipts, verify_receipt):
    cur.execute("SELECT to_regclass('evidence_pipeline.windows_inventory_bindings')")
    if cur.fetchone()[0] is None:
        require(
            not any(s["source_name"] == "Windows inventory" for s in sources.values()),
            "Windows inventory schema missing",
        )
        return
    bindings = {
        r["connection_id"]: r
        for r in rows(cur, "evidence_pipeline.windows_inventory_bindings")
    }
    expected = {
        key
        for key, source in sources.items()
        if source["source_name"] == "Windows inventory"
    }
    require(
        set(bindings) == expected, "Windows inventory authority differs from bindings"
    )
    for key in bindings:
        cur.execute(
            "SELECT evidence_pipeline.valid_windows_inventory_binding(%s)", (key,)
        )
        require(cur.fetchone() == (True,), "Invalid Windows inventory device binding")
    runs = {
        r["attempt_id"]: r
        for r in rows(cur, "evidence_pipeline.windows_inventory_runs")
    }
    require(
        set(runs)
        == {
            key
            for key, a in attempts.items()
            if a["connection_id"] in bindings and a["complete"]
        },
        "Windows inventory runs differ from complete attempts",
    )
    providers = {r["id"]: r for r in rows(cur, "evidence.provider_devices")}
    device_receipts = {
        (
            o["provider_device_id"],
            receipts.get(o["receipt_id"], {}).get("collection_attempt_id"),
        )
        for o in rows(cur, "evidence.device_observations")
    }
    tenants = {
        r["id"]: r["external_tenant_id"]
        for r in rows(cur, "evidence.microsoft_tenants")
    }
    for key, run in runs.items():
        bound = bindings[attempts[key]["connection_id"]]
        device = attempts.get(run["device_attempt_id"])
        provider = providers.get(run["provider_device_id"])
        require(
            device is not None
            and device["complete"]
            and device["connection_id"] == bound["device_connection_id"]
            and provider is not None
            and provider["connection_id"] == bound["device_connection_id"]
            and provider["native_device_id"] == bound["native_device_id"]
            and provider["microsoft_registration_id"] == bound["entra_device_id"],
            "Windows inventory pinned device changed",
        )
        require(
            (provider["id"], run["device_attempt_id"]) in device_receipts,
            "Windows inventory pinned device receipt missing",
        )
    counts = Counter()
    identities = set()
    for record in rows(cur, "evidence_pipeline.windows_inventory_observations"):
        key = record["attempt_id"]
        require(
            key in runs
            and receipts.get(record["receipt_id"], {}).get("collection_attempt_id")
            == key,
            "Windows inventory observation has no matching run",
        )
        bound = bindings[attempts[key]["connection_id"]]
        tenant = sources[attempts[key]["connection_id"]]["tenant_id"]
        binding = DeviceBinding(
            bound["machine_guid"], tenants[tenant], bound["entra_device_id"]
        )
        facts = record["facts"]
        identity = (key, record["kind"], record["native_id"])
        require(
            identity not in identities
            and facts.get("kind") == record["kind"]
            and facts.get("native_id") == record["native_id"],
            "Windows inventory source identity changed",
        )
        identities.add(identity)
        verify_receipt(
            record["receipt_id"],
            observation_key(binding, facts),
            digest(facts),
            "exposure",
        )
        counts[key] += 1
    require(
        all(counts[key] == run["record_count"] for key, run in runs.items()),
        "Windows inventory source record count changed",
    )
