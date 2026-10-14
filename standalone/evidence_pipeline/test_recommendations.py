"""Synthetic provider advice and explicit associations, without CVE inference."""

from dataclasses import replace
import json

import pytest

from .test_vulnerability_catalogue import snapshot
from standalone.evidence_pipeline.parsing.recommendations import (
    normalize_recommendations,
)


def normalize(raw, links):
    source = snapshot([])
    source = replace(
        source,
        scope=replace(source.scope, input_kind="recommendations"),
        payload=json.dumps(raw).encode(),
    )
    return normalize_recommendations(source, links, {"synthetic-device"})


def record(**changes):
    return {
        "id": "synthetic-recommendation",
        "recommendationName": "Synthetic configuration advice",
        "remediationType": "ConfigurationChange",
        **changes,
    }


def test_advice_without_cve_kb_or_device_links_is_retained():
    item = normalize([record()], {"synthetic-recommendation": []})[0]
    assert item.native_device_ids == ()
    assert item.observation()["remediation_type"] == "ConfigurationChange"
    assert item.observation()["product_name"] is None


def test_explicit_device_links_and_provider_counts_remain_distinct():
    item = normalize(
        [record(exposedMachinesCount=2)],
        {"synthetic-recommendation": ["synthetic-device"]},
    )[0]
    assert item.native_device_ids == ("synthetic-device",)
    assert dict(item.source_counts)["exposedMachinesCount"] == 2


@pytest.mark.parametrize(
    "raw,links",
    [
        ([record()], {}),
        ([record(), record()], {"synthetic-recommendation": []}),
        ([record()], {"synthetic-recommendation": [None]}),
        ([record()], {"synthetic-recommendation": [""]}),
        ([record()], {"synthetic-recommendation": ["synthetic-device"] * 2}),
        ([], {"synthetic-recommendation": []}),
        ([record(recommendationName=None)], {"synthetic-recommendation": []}),
        ([record(totalMachineCount=-1)], {"synthetic-recommendation": []}),
    ],
)
def test_partial_or_invalid_associations_are_not_a_complete_snapshot(raw, links):
    with pytest.raises(ValueError):
        normalize(raw, links)


def test_unknown_device_reference_is_explicitly_unbound():
    (item,) = normalize([record()], {"synthetic-recommendation": ["synthetic-retired"]})
    assert (
        item.native_device_ids
        == item.unbound_native_device_ids
        == ("synthetic-retired",)
    )
