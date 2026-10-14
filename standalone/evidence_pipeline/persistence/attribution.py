"""Verify pipeline additions before separating them from original fixture checks.

No arbitrary row-count exclusions: registered scopes, receipts, content hashes
and deterministic identities must explain each retained pipeline row.
"""

from dataclasses import asdict
import hashlib
import json
import re

from standalone.evidence_pipeline.parsing.devices import (
    TEXT_FIELDS,
    TIME_FIELDS,
    BOOL_FIELDS,
    stable_id,
    timestamp,
)
from standalone.evidence_pipeline.parsing.exposure import (
    Software,
    SoftwareInventory,
    Finding,
    software,
)


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def digest(value):
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, ensure_ascii=False, separators=(",", ":")
        ).encode()
    ).hexdigest()


def rows(cur, table):
    from psycopg2 import sql

    schema, name = table.split(".")
    cur.execute(
        sql.SQL("SELECT to_jsonb(t) FROM {} t").format(sql.Identifier(schema, name))
    )
    return [row[0] for row in cur.fetchall()]


def retained_device_fields(source, observation):
    """Reconstruct importer timestamp encoding after PostgreSQL JSON round trips."""
    fields = {
        k: observation[k]
        for k in {
            **TEXT_FIELDS[source],
            **TIME_FIELDS[source],
            **BOOL_FIELDS[source],
        }
    }
    if source == "Defender":
        fields["os_build"] = observation["os_build"]
        for field in ("os_architecture", "os_processor"):
            if observation.get(field) is not None:
                fields[field] = observation[field]
    for field in TIME_FIELDS[source]:
        fields[field] = timestamp(fields[field], field)
    return fields


def separate_pipeline(cur, extras, *, spool):
    cur.execute("SELECT to_regclass('evidence_pipeline.installation')")
    if cur.fetchone()[0] is None:
        return extras
    from backend.database.schema import verify_supported

    # Read-only shared verification handles the current baseline and the sole
    # explicit adoption predecessor, without traversing historical migrations.
    verify_supported(cur)
    from standalone.evidence_pipeline.persistence.enrichment_attribution import (
        verify_enrichment,
    )

    verify_enrichment(cur)
    from standalone.evidence_pipeline.persistence.osv_query_attribution import (
        verify_osv_queries,
    )

    verify_osv_queries(cur)
    authorized = {
        r["connection_id"]: r["origin"]
        for r in rows(cur, "evidence_pipeline.authorized_connections")
    }
    if not authorized:
        from standalone.evidence_pipeline.persistence.cve_attribution import (
            verify_cve_inventory,
        )

        verify_cve_inventory(cur, {})
        from standalone.evidence_pipeline.persistence.osv_attribution import (
            verify_osv_inventory,
        )

        verify_osv_inventory(cur, {})
        from standalone.evidence_pipeline.persistence.reference_attribution import (
            verify_reference_inventory,
        )

        verify_reference_inventory(cur, set())
        return extras
    remaining = dict(extras)
    sources = {
        r["id"]: r for r in extras["source_connections"] if r["id"] in authorized
    }
    require(
        set(sources) == set(authorized),
        "Pipeline registration must reference a pipeline source",
    )
    tenants = {r["id"]: r for r in extras["microsoft_tenants"]}
    used_tenants = set()
    for key, source in sources.items():
        is_public = (source["source_name"], source["input_kind"]) in {
            ("FIRST", "epss"),
            ("CISA", "kev"),
            ("NVD", "vulnerabilities"),
            ("MSRC", "advisories"),
            ("MSRC", "security_updates"),
            ("CVE", "records"),
            ("OSV", "advisories"),
            ("GitHub", "advisories"),
            ("Ubuntu", "advisories"),
            ("Red Hat", "advisories"),
            ("Debian", "tracker"),
            ("Apache HTTP Server", "advisories"),
            ("Apache Tomcat", "advisories"),
            ("Samba", "advisories"),
            ("Palo Alto Networks", "advisories"),
            ("Microsoft Update Catalog", "updates"),
            ("Cisco", "advisories"),
            ("WA SOC", "advisories"),
            ("Exploit-DB", "metadata"),
            ("CTID", "cve_mappings"),
            ("MITRE ATT&CK", "enterprise_definitions"),
            ("CISA", "vulnrichment"),
        }
        if is_public:
            require(
                authorized[key] in ("synthetic", "public")
                and source["tenant_id"] is None,
                "Invalid public source origin or tenant",
            )
            require(
                re.fullmatch(
                    r"evidence-pipeline-v1:" + authorized[key] + r":[0-9a-f]{64}",
                    source["collector_reference"] or "",
                )
                is not None,
                "Invalid public source provenance",
            )
            continue
        require(authorized[key] in ("synthetic", "lab"), "Unrecognized pipeline origin")
        require(
            (source["source_name"], source["input_kind"])
            in {
                ("Entra", "devices"),
                ("Intune", "devices"),
                ("Defender", "devices"),
                ("Intune", "software"),
                ("Defender", "findings"),
                ("Defender", "missing_patches"),
                ("Defender", "antivirus"),
                ("Defender", "vulnerability_catalogue"),
                ("Defender", "vulnerability_baseline"),
                ("Defender", "vulnerability_events"),
                ("Defender", "recommendations"),
                ("Intune", "update_status"),
                ("Windows inventory", "software_inventory"),
            },
            "Unrecognized pipeline input",
        )
        tenant = tenants.get(source["tenant_id"])
        require(
            tenant is not None and tenant["cloud_label"] == "Microsoft",
            "Unexplained pipeline tenant",
        )
        require(
            tenant["id"]
            == stable_id("tenant", authorized[key], tenant["external_tenant_id"]),
            "Pipeline tenant identity changed",
        )
        require(
            re.fullmatch(
                r"evidence-pipeline-v1:" + authorized[key] + r":[0-9a-f]{64}",
                source["collector_reference"] or "",
            )
            is not None,
            "Invalid pipeline source provenance",
        )
        require(
            tenant.get("evidence_origin", "synthetic") == authorized[key],
            "Tenant evidence origin differs from connection",
        )
        used_tenants.add(tenant["id"])
    attempts = {
        r["id"]: r
        for r in extras["collection_attempts"]
        if r["connection_id"] in sources
    }
    revisions = spool.reference_mapping(
        extras["source_revisions"], "id", lambda r: r["connection_id"] in sources
    )
    receipts = spool.reference_mapping(
        extras["observation_receipts"],
        "id",
        lambda r: r["collection_attempt_id"] in attempts,
    )
    providers = {
        r["id"]: r for r in extras["provider_devices"] if r["connection_id"] in sources
    }
    for attempt in attempts.values():
        require(
            attempt["revision"] == 1
            and attempt["outcome"] in ("success", "failure")
            and attempt["complete"] == (attempt["outcome"] == "success")
            and attempt["finished_at"] is not None
            and re.fullmatch(r"[0-9a-f]{64}", attempt["input_fingerprint"] or "")
            is not None,
            "Invalid pipeline attempt",
        )
    for provider in providers.values():
        source = sources[provider["connection_id"]]
        require(
            source["input_kind"] == "devices"
            and provider["id"]
            == stable_id("provider-device", source["id"], provider["native_device_id"]),
            "Invalid pipeline provider identity",
        )
    for receipt in receipts.values():
        revision = revisions.get(receipt["source_revision_id"])
        attempt = attempts[receipt["collection_attempt_id"]]
        require(
            revision is not None
            and revision["connection_id"] == attempt["connection_id"]
            and attempt["complete"],
            "Pipeline receipt has invalid source or failed attempt",
        )
    received_revisions = {r["source_revision_id"] for r in receipts.values()}
    for revision in revisions.values():
        source = sources[revision["connection_id"]]
        require(
            revision["origin"] == authorized[source["id"]]
            and revision["source_url"]
            == (source["scope_reference"] if source["tenant_id"] is None else None)
            and revision["source_updated_at"] is None
            and source["collector_reference"].endswith(
                hashlib.sha256(revision["licence_or_provenance"].encode()).hexdigest()
            ),
            "Pipeline revision provenance changed",
        )
        require(
            revision["id"] in received_revisions,
            "Orphan pipeline revision",
        )

    explained = {name: set() for name in extras}
    explained["source_connections"] = set(sources)
    explained["microsoft_tenants"] = used_tenants
    explained["collection_attempts"] = set(attempts)
    explained["source_revisions"] = set(revisions)
    explained["observation_receipts"] = set(receipts)
    explained["provider_devices"] = set(providers)
    used_receipts = set()

    def verify_receipt(receipt_id, source_id, content_hash, kind):
        require(
            receipt_id in receipts and receipt_id not in used_receipts,
            "Unexplained or duplicate pipeline receipt",
        )
        received = receipts[receipt_id]
        revision = revisions[received["source_revision_id"]]
        expected_revision = stable_id(
            kind + "-revision", revision["connection_id"], source_id, content_hash
        )
        require(
            revision["source_record_id"] == source_id
            and revision["content_hash"] == content_hash
            and revision["id"] == expected_revision
            and receipt_id
            == stable_id(
                kind + "-receipt", expected_revision, received["collection_attempt_id"]
            ),
            "Pipeline content hash or receipt identity changed",
        )
        used_receipts.add(receipt_id)

    from standalone.evidence_pipeline.persistence.windows_inventory_attribution import (
        verify_windows_inventory,
    )

    verify_windows_inventory(cur, sources, attempts, receipts, verify_receipt)

    for observation in extras["device_observations"]:
        if observation["receipt_id"] not in receipts:
            continue
        provider = providers.get(observation["provider_device_id"])
        require(
            provider is not None,
            "Pipeline observation references another provider scope",
        )
        source = sources[provider["connection_id"]]["source_name"]
        fields = retained_device_fields(source, observation)

        registration = provider["microsoft_registration_id"]
        issues = (
            [None]
            if registration
            else ["missing_registration_id", "invalid_registration_id"]
        )
        hashes = [
            digest([source, provider["native_device_id"], registration, issue, fields])
            for issue in issues
        ]
        require(
            all(
                value is None
                for key, value in observation.items()
                if key not in set(fields) | {"id", "provider_device_id", "receipt_id"}
            ),
            "Unexpected device observation fields",
        )
        actual = revisions[receipts[observation["receipt_id"]]["source_revision_id"]][
            "content_hash"
        ]
        require(
            actual in hashes and observation["observed_at"] is None,
            "Device evidence content changed",
        )
        verify_receipt(
            observation["receipt_id"], provider["native_device_id"], actual, "device"
        )
        require(
            observation["id"]
            == stable_id(
                "device-observation", observation["receipt_id"], provider["id"]
            ),
            "Device observation identity changed",
        )
        explained["device_observations"].add(observation["id"])

    cur.execute("SELECT to_regclass('evidence_pipeline.exposure_snapshots')")
    if cur.fetchone()[0] is not None:
        cur.execute("SELECT evidence_pipeline.validate_exposure()")
        catalog = {r["id"]: Software(**r) for r in rows(cur, "evidence.software")}
        inventory = rows(cur, "evidence_pipeline.software_inventory")
        contexts = rows(cur, "evidence_pipeline.exposure_snapshots")
        require(
            all(r["collection_attempt_id"] in attempts for r in contexts),
            "Unexplained exposure context",
        )
        links = extras["software_observations"]
        for app in inventory:
            require(app["receipt_id"] in receipts, "Unexplained software inventory")
            item_links = [r for r in links if r["inventory_id"] == app["id"]]
            native = tuple(
                sorted(
                    providers[r["provider_device_id"]]["native_device_id"]
                    for r in item_links
                )
            )
            product = catalog[app["software_id"]]
            require(
                product
                == software(
                    product.product_name,
                    product.publisher,
                    product.version,
                    product.platform,
                ),
                "Software catalogue identity changed",
            )
            content = asdict(
                SoftwareInventory(
                    app["source_application_id"],
                    product,
                    native,
                    app["reported_device_count"],
                )
            )
            verify_receipt(
                app["receipt_id"],
                app["source_application_id"],
                digest(content),
                "exposure",
            )
            require(
                app["id"] == stable_id("software-inventory", app["receipt_id"]),
                "Inventory identity changed",
            )
            for link in item_links:
                require(
                    link["id"]
                    == stable_id(
                        "software-observation", app["id"], link["provider_device_id"]
                    )
                    and link["observed_at"] is None,
                    "Software link identity changed",
                )
                explained["software_observations"].add(link["id"])
            explained["software"].add(product.id)
        epss_cves = {r["cve_id"] for r in extras["epss_observations"]}
        for finding in extras["vulnerability_findings"]:
            if finding["receipt_id"] not in receipts:
                continue
            product = catalog[finding["software_id"]]
            require(
                product
                == software(
                    product.product_name,
                    product.publisher,
                    product.version,
                    product.platform,
                ),
                "Finding software identity changed",
            )
            content = asdict(
                Finding(
                    finding["source_finding_id"],
                    providers[finding["provider_device_id"]]["native_device_id"],
                    product,
                    finding["cve_id"],
                    finding["source_severity_label"],
                    finding["fixing_patch_reference"],
                )
            )
            verify_receipt(
                finding["receipt_id"],
                finding["source_finding_id"],
                digest(content),
                "exposure",
            )
            require(
                finding["id"]
                == stable_id("vulnerability-finding", finding["receipt_id"])
                and finding["fixing_patch_id"] is None
                and finding["observed_at"] is None,
                "Finding identity or unsupported patch claim changed",
            )
            explained["vulnerability_findings"].add(finding["id"])
            explained["software"].add(product.id)
            if finding["cve_id"] not in epss_cves:
                explained["vulnerabilities"].add(finding["cve_id"])
    from standalone.evidence_pipeline.persistence.update_attribution import (
        verify_updates,
    )

    verify_updates(
        extras,
        sources,
        revisions,
        receipts,
        attempts,
        providers,
        explained,
        verify_receipt,
    )
    from standalone.evidence_pipeline.persistence.antivirus_attribution import (
        verify_antivirus,
    )

    verify_antivirus(
        extras,
        sources,
        revisions,
        receipts,
        attempts,
        providers,
        explained,
        verify_receipt,
    )
    cur.execute("SELECT to_regclass('evidence_pipeline.public_claims')")
    if cur.fetchone()[0] is not None:
        from standalone.evidence_pipeline.persistence.public_attribution import (
            verify_public,
        )

        verify_public(
            cur, extras, sources, revisions, receipts, explained, verify_receipt, spool
        )
    cur.execute("SELECT to_regclass('evidence_pipeline.catalogue_observations')")
    if cur.fetchone()[0] is not None:
        seen_catalogue = set()
        for observation in rows(cur, "evidence_pipeline.catalogue_observations"):
            received = receipts.get(observation["receipt_id"])
            require(received is not None, "Unexplained catalogue receipt")
            attempt = attempts[received["collection_attempt_id"]]
            source = sources[attempt["connection_id"]]
            require(
                (source["source_name"], source["input_kind"])
                == ("Defender", "vulnerability_catalogue"),
                "Catalogue source differs",
            )
            key = (attempt["id"], observation["cve_id"])
            require(key not in seen_catalogue, "Duplicate catalogue CVE in attempt")
            seen_catalogue.add(key)
            verify_receipt(
                observation["receipt_id"],
                json.dumps(["catalogue", observation["cve_id"]], separators=(",", ":")),
                digest(observation["claim"]),
                "exposure",
            )
            if observation["cve_id"] not in epss_cves:
                explained["vulnerabilities"].add(observation["cve_id"])
    cur.execute("SELECT to_regclass('evidence_pipeline.assessment_observations')")
    if cur.fetchone()[0] is not None:
        bindings = {
            item["connection_id"]: item
            for item in rows(cur, "evidence_pipeline.assessment_bindings")
        }
        runs = {
            item["attempt_id"]: item
            for item in rows(cur, "evidence_pipeline.assessment_runs")
        }
        for observation in rows(cur, "evidence_pipeline.assessment_observations"):
            received = receipts.get(observation["receipt_id"])
            require(received is not None, "Unexplained assessment receipt")
            attempt = attempts[received["collection_attempt_id"]]
            source = sources[attempt["connection_id"]]
            require(
                source["input_kind"]
                in ("vulnerability_baseline", "vulnerability_events"),
                "Assessment source differs",
            )
            run = runs.get(attempt["id"])
            binding = bindings.get(source["id"])
            provider = providers.get(observation["provider_device_id"])
            claim = observation["claim"]
            require(
                run is not None
                and binding is not None
                and (
                    provider is None
                    or provider["connection_id"] == binding["device_connection_id"]
                ),
                "Assessment binding differs",
            )
            require(
                (
                    provider is None
                    or claim["native_device_id"] == provider["native_device_id"]
                )
                and claim["cve_id"] == observation["cve_id"]
                and claim["event_kind"] == observation["event_kind"]
                and claim["event_time_raw"] == observation["event_time_text"]
                and claim["fingerprint"] == observation["event_fingerprint"],
                "Assessment projection changed",
            )
            candidates = {
                row["provider_device_id"]
                for row in extras["device_observations"]
                if row["receipt_id"] in receipts
                and receipts[row["receipt_id"]]["collection_attempt_id"]
                == run["device_attempt_id"]
                and providers[row["provider_device_id"]]["connection_id"]
                == binding["device_connection_id"]
                and providers[row["provider_device_id"]]["native_device_id"]
                == claim["native_device_id"]
            }
            require(
                candidates == ({provider["id"]} if provider else set()),
                "Assessment device link does not match pinned evidence",
            )
            require(
                claim.get("device_bound", provider is not None)
                == (provider is not None),
                "Assessment link state changed",
            )
            from datetime import datetime

            actual_time = observation["event_time_utc"]
            claimed_time = claim["event_time_utc"]
            require(
                (datetime.fromisoformat(actual_time) if actual_time else None)
                == (datetime.fromisoformat(claimed_time) if claimed_time else None),
                "Assessment absolute source time changed",
            )
            require(
                json.loads(observation["instance_key"])
                == [claim["native_device_id"], claim["product"]["id"], claim["cve_id"]],
                "Assessment instance identity changed",
            )
            require(
                (source["input_kind"] == "vulnerability_events")
                == (observation["event_kind"] is not None),
                "Baseline/event kind changed",
            )
            verify_receipt(
                observation["receipt_id"],
                observation["event_fingerprint"],
                digest(claim),
                "exposure",
            )
            if (
                observation["cve_id"] is not None
                and observation["cve_id"] not in epss_cves
            ):
                explained["vulnerabilities"].add(observation["cve_id"])
    cur.execute("SELECT to_regclass('evidence_pipeline.recommendation_claims')")
    if cur.fetchone()[0] is not None:
        from standalone.evidence_pipeline.persistence.recommendation_attribution import (
            verify_recommendations,
        )

        verify_recommendations(
            cur,
            extras,
            sources,
            receipts,
            attempts,
            providers,
            explained,
            verify_receipt,
        )
    decisions = extras["classification_decisions"]
    by_device = {}
    for decision in decisions:
        require(
            decision["provider_device_id"] in providers,
            "Classification targets an unexplained provider",
        )
        require(
            decision["actor_kind"] == "analyst"
            and decision["actor_reference"] == "local operator",
            "Classification actor changed",
        )
        require(
            isinstance(decision["selected_type"], str)
            and 0 < len(decision["selected_type"].strip())
            and len(decision["selected_type"]) <= 128,
            "Invalid classification type",
        )
        require(
            isinstance(decision["reason"], str)
            and 0 < len(decision["reason"].strip())
            and len(decision["reason"]) <= 4000
            and decision["decided_at"] is not None,
            "Invalid classification reason or time",
        )
        by_device.setdefault(decision["provider_device_id"], []).append(decision)
    for history in by_device.values():
        previous = None
        for revision, decision in enumerate(
            sorted(history, key=lambda row: row["revision"]), 1
        ):
            require(
                decision["revision"] == revision
                and decision["supersedes_decision_id"] == previous,
                "Classification decision history changed",
            )
            previous = decision["id"]
            explained["classification_decisions"].add(previous)
    require(
        used_receipts == set(receipts), "Pipeline receipt has no matching observation"
    )
    observed_providers = {
        r["provider_device_id"]
        for r in extras["device_observations"]
        if r["id"] in explained["device_observations"]
    }
    require(observed_providers == set(providers), "Orphan pipeline provider device")
    cur.execute("SELECT to_regclass('evidence_pipeline.notification_episodes')")
    if cur.fetchone()[0] is not None:
        projected = {
            row["id"]: row
            for row in rows(cur, "evidence_pipeline.notification_episodes")
        }
        actual = {row["id"]: row for row in extras["notifications"]}
        require(
            set(projected) == set(actual),
            "Notification episodes differ from collection history",
        )
        associations = set()
        for key, expected in projected.items():
            expected = dict(expected)
            associations.update((key, item) for item in expected.pop("failure_ids"))
            stored = dict(actual[key])
            revision = stored.pop("revision")
            require(
                type(revision) is int and revision > 0 and stored == expected,
                "Notification state differs from collection evidence",
            )
        require(
            {
                (row["notification_id"], row["collection_attempt_id"])
                for row in extras["notification_attempts"]
            }
            == associations,
            "Notification attempt membership differs",
        )
        explained["notifications"] = set(projected)
        remaining["notification_attempts"] = []
    from standalone.evidence_pipeline.persistence.csaf_attribution import (
        KEYS,
        key as advisory_key,
    )

    for name, records in remaining.items():
        if name == "recommendation_devices":
            remaining[name] = spool.rows(
                r
                for r in records
                if (r["recommendation_id"], r["provider_device_id"], r["receipt_id"])
                not in explained[name]
            )
            continue
        if name in KEYS:
            remaining[name] = spool.rows(
                r for r in records if advisory_key(name, r) not in explained[name]
            )
            continue
        key = "cve_id" if name == "vulnerabilities" else "id"
        remaining[name] = spool.rows(
            r for r in records if r.get(key) not in explained[name]
        )
    return remaining
