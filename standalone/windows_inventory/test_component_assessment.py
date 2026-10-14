"""Synthetic workflow adapter checks; no production applicability assertions."""

from dataclasses import replace
from datetime import timedelta
import hashlib
import io
import json
from uuid import uuid4

import pytest

from .component_assessment import canonical, prepare
from .staging import stage
from .test_component_check import case, run, SOURCE, DIGEST
from .test_contract import BINDING


def test_normal_no_rule_import_retains_unknowns_and_exact_facts():
    raw, _, _ = case()
    with stage(io.BytesIO(raw), BINDING) as inventory:
        with prepare(inventory, binding=BINDING, origin="synthetic") as checked:
            metadata = checked.metadata
            rows = list(checked.results())
            assert metadata["inventory_sha256"] == hashlib.sha256(raw).hexdigest()
            assert metadata["defender_coverage"] == "unverified"
            assert metadata["context_available"] is False
            assert metadata["result_count"] == 2
            assert metadata["rules"] == []
            assert all(r["state"] == "unknown" and r["evaluations"] == [] for r in rows)
            for row, source in zip(rows, json.loads(raw)["records"], strict=True):
                assert (
                    row["facts_sha256"]
                    == hashlib.sha256(canonical(source).encode()).hexdigest()
                )
            assert rows == list(checked.results())
            metadata["result_count"] = 99
            assert checked.metadata["result_count"] == 2
        assert checked.results_file.closed


@pytest.mark.parametrize("version", ["1.2.3.4", "1.2.3.5", "1.2.3.10"])
def test_streamed_evaluations_agree_with_offline_checker(version):
    raw, context, rule = case(version)
    expected = run(raw, context, [rule])
    with stage(io.BytesIO(raw), BINDING) as inventory:
        digests = []
        for _ in range(2):
            with prepare(
                inventory,
                binding=BINDING,
                origin="synthetic",
                context=context,
                rules=[rule],
                retained_sources={DIGEST: SOURCE},
            ) as checked:
                rows = list(checked.results())
                for row in rows:
                    row.pop("facts_sha256")
                assert rows == expected["rows"]
                digests.append(checked.metadata["results_sha256"])
        assert digests[0] == digests[1]


@pytest.mark.parametrize(
    "change",
    [
        {"inventory_sha256": "0" * 64},
        {"binding": replace(BINDING, device_id=str(uuid4()))},
        {"origin": "lab"},
        {"observed_at": "late"},
    ],
)
def test_wrong_snapshot_device_origin_or_time_cannot_publish(change):
    raw, context, rule = case()
    if change.get("observed_at") == "late":
        change = {"observed_at": context.observed_at + timedelta(days=1)}
    with stage(io.BytesIO(raw), BINDING) as inventory:
        with pytest.raises(ValueError):
            with prepare(
                inventory,
                binding=BINDING,
                origin="synthetic",
                context=replace(context, **change),
                rules=[rule],
                retained_sources={DIGEST: SOURCE},
            ):
                pytest.fail("Invalid attribution published")


def test_changed_installed_version_invalidates_old_context():
    raw, context, rule = case()
    newer, _, _ = case("1.2.3.5")
    assert raw != newer
    with stage(io.BytesIO(newer), BINDING) as inventory:
        with pytest.raises(ValueError, match="snapshot"):
            with prepare(
                inventory,
                binding=BINDING,
                origin="synthetic",
                context=context,
                rules=[rule],
                retained_sources={DIGEST: SOURCE},
            ):
                pytest.fail("Old context applied to changed installed version")


def test_rules_without_context_and_altered_sources_rejected():
    raw, context, rule = case()
    with stage(io.BytesIO(raw), BINDING) as inventory:
        for kwargs in (
            {"rules": [rule]},
            {
                "context": context,
                "rules": [rule],
                "retained_sources": {DIGEST: b"changed"},
            },
        ):
            with pytest.raises(ValueError):
                with prepare(inventory, binding=BINDING, origin="synthetic", **kwargs):
                    pytest.fail("Missing or altered evidence accepted")


def test_interruption_cannot_expose_partial_evaluation(monkeypatch):
    raw, _, _ = case()
    with stage(io.BytesIO(raw), BINDING) as inventory:
        original = inventory.records

        def interrupted():
            yield next(original())
            raise KeyboardInterrupt

        monkeypatch.setattr(inventory, "records", interrupted)
        with pytest.raises(KeyboardInterrupt):
            with prepare(inventory, binding=BINDING, origin="synthetic"):
                pytest.fail("Interrupted check exposed partial results")


def test_cancellation_during_result_read_is_not_success():
    raw, _, _ = case()
    cancelled = False
    with stage(io.BytesIO(raw), BINDING, cancelled=lambda: cancelled) as inventory:
        with prepare(inventory, binding=BINDING, origin="synthetic") as checked:
            iterator = checked.results()
            next(iterator)
            cancelled = True
            with pytest.raises(ValueError, match="cancelled"):
                next(iterator)


def test_source_bytes_and_context_survive_replay_without_unreferenced_data():
    raw, context, rule = case()
    sources = {DIGEST: SOURCE, "unreferenced": b"must not be persisted"}
    with stage(io.BytesIO(raw), BINDING) as inventory:
        with prepare(
            inventory,
            binding=BINDING,
            origin="synthetic",
            context=context,
            rules=[rule],
            retained_sources=sources,
        ) as checked:
            sources[DIGEST] = b"caller changed mapping"
            chunks = list(checked.source_chunks())
            assert chunks == list(checked.source_chunks())
            assert set(h for h, _, _ in chunks) == {DIGEST, inventory.fingerprint}
            assert b"".join(b for h, _, b in chunks if h == DIGEST) == SOURCE
            assert (
                b"".join(b for h, _, b in chunks if h == inventory.fingerprint) == raw
            )
            assert (
                checked.metadata["context"]["binding"]["device_id"] == BINDING.device_id
            )


def test_source_tampering_is_detected_before_transaction_can_finish():
    raw, _, _ = case()
    with stage(io.BytesIO(raw), BINDING) as inventory:
        with prepare(inventory, binding=BINDING, origin="synthetic") as checked:
            inventory.source_file.seek(0)
            inventory.source_file.write(b"changed")
            with pytest.raises(ValueError, match="source changed"):
                list(checked.source_chunks())
