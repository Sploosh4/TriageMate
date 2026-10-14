"""Reconstruct Defender advice and exact links from retained source claims."""

from standalone.evidence_pipeline.parsing.devices import stable_id


def verify_recommendations(
    cur, extras, sources, receipts, attempts, providers, explained, verify_receipt
):
    from standalone.evidence_pipeline.persistence.attribution import (
        rows,
        require,
        digest,
    )

    bindings = {
        r["connection_id"]: r
        for r in rows(cur, "evidence_pipeline.recommendation_bindings")
    }
    runs = {
        r["attempt_id"]: r for r in rows(cur, "evidence_pipeline.recommendation_runs")
    }
    recommendations = {r["id"]: r for r in extras["recommendations"]}
    edges = extras["recommendation_devices"]
    observed = {
        (r["provider_device_id"], receipts[r["receipt_id"]]["collection_attempt_id"])
        for r in extras["device_observations"]
        if r["receipt_id"] in receipts
    }
    for observation in rows(cur, "evidence_pipeline.recommendation_claims"):
        received = receipts.get(observation["receipt_id"])
        require(received is not None, "Unexplained recommendation receipt")
        attempt = attempts[received["collection_attempt_id"]]
        source = sources[attempt["connection_id"]]
        require(
            (source["source_name"], source["input_kind"])
            == ("Defender", "recommendations"),
            "Recommendation source differs",
        )
        run, binding = runs.get(attempt["id"]), bindings.get(source["id"])
        require(
            run is not None and binding is not None, "Recommendation binding missing"
        )
        device_attempt = attempts.get(run["device_attempt_id"])
        require(
            device_attempt is not None
            and device_attempt["complete"]
            and device_attempt["outcome"] == "success"
            and device_attempt["connection_id"] == binding["device_connection_id"],
            "Recommendation device execution differs",
        )
        claim = observation["claim"]
        verify_receipt(
            observation["receipt_id"], claim["source_id"], digest(claim), "exposure"
        )
        key = stable_id("defender-recommendation", observation["receipt_id"])
        expected = {
            "id": key,
            "source_recommendation_id": claim["source_id"],
            "advisory_id": None,
            "recommendation_text": None,
            "receipt_id": observation["receipt_id"],
            **claim["fields"],
        }
        require(
            recommendations.get(key) == expected, "Recommendation projection changed"
        )
        explained["recommendations"].add(key)
        linked = [e for e in edges if e["recommendation_id"] == key]
        natives = []
        for edge in linked:
            provider = providers.get(edge["provider_device_id"])
            require(
                provider is not None
                and provider["connection_id"] == binding["device_connection_id"]
                and (provider["id"], run["device_attempt_id"]) in observed
                and edge["receipt_id"] == observation["receipt_id"],
                "Recommendation association binding changed",
            )
            natives.append(provider["native_device_id"])
            explained["recommendation_devices"].add(
                (key, provider["id"], edge["receipt_id"])
            )
        require(
            sorted(natives)
            == sorted(
                native
                for native in claim["native_device_ids"]
                if any(
                    p["native_device_id"] == native
                    and p["connection_id"] == binding["device_connection_id"]
                    and (p["id"], run["device_attempt_id"]) in observed
                    for p in providers.values()
                )
            ),
            "Recommendation association membership changed",
        )
