"""Explicit synthetic inputs, private config files and fixed source routes."""

from dataclasses import asdict
import json

import pytest

from .test_process_worker import scope
from .configuration import load
from .checkpoint import encode, decode
from .test_dispatch import NOW


def configuration(tmp_path):
    root = tmp_path / "bundles"
    root.mkdir(mode=0o700)
    fixture = tmp_path / "synthetic.csv"
    fixture.write_text("explicitly synthetic test placeholder; not collected")
    fixture.chmod(0o600)
    item = dict(
        scope=asdict(scope()),
        schedule=dict(
            kind="interval", seconds=3600, anchor=NOW.isoformat(), offset_seconds=120
        ),
        bundle_root=str(root),
        synthetic_input=str(fixture),
        allow_network=False,
        parameters={},
    )
    return dict(version=1, concurrency=1, grace_seconds=60, inputs=[item])


def save(tmp_path, document):
    path = tmp_path / "configuration.json"
    path.write_text(json.dumps(document))
    path.chmod(0o600)
    return path


@pytest.mark.parametrize(
    "damage", [None, "route", "network", "budget", "parameter", "tenant"]
)
@pytest.mark.parametrize(
    "source",
    [
        "Ubuntu",
        "Red Hat",
        "Microsoft Update Catalog",
        "Cisco",
        "WA SOC",
        "MSRC",
        "CVE",
        "CISA",
    ],
)
def test_repository_configuration_is_explicit_and_bounded(tmp_path, damage, source):
    from .repository_recipe import RepositoryRecipe
    from .repository_recipe import SOURCE_URLS
    from uuid import uuid4

    document = configuration(tmp_path)
    item = document["inputs"][0]
    item["scope"].update(
        source=source,
        input_kind="repository",
        scope_reference=SOURCE_URLS[source],
    )
    item["parameters"] = dict(metadata_limit=2, record_limit=1, pass_limit=10)
    if source in {"CVE", "CISA", "WA SOC"}:
        item["provider_age_seconds"] = 86400
    if source == "MSRC":
        item["parameters"] = dict(
            starting_month="2099-Jan", retained_ids=[], record_limit=1, pass_limit=10
        )
    elif source in {"Red Hat", "Cisco"}:
        del item["parameters"]["metadata_limit"]
    elif source == "Microsoft Update Catalog":
        item["scope"].update(
            input_kind="catalog_search",
            scope_reference=SOURCE_URLS[source] + "?q=KB9999991",
        )
        item["parameters"] = dict(kb="KB9999991", record_limit=1, pass_limit=10)
        item["provider_age_seconds"] = 86400
    if damage == "route":
        item["scope"]["scope_reference"] += "/arbitrary"
    elif damage == "network":
        item["allow_network"] = True
    elif damage == "budget":
        item["parameters"]["pass_limit"] = True
    elif damage == "parameter":
        item["parameters"]["arbitrary_url"] = "https://example.invalid"
    elif damage == "tenant":
        item["scope"]["tenant_id"] = str(uuid4())
    if damage or source in {"Ubuntu", "Red Hat", "Cisco"}:
        with pytest.raises(ValueError):
            load(save(tmp_path, document), now=NOW)
    else:
        result = load(save(tmp_path, document), now=NOW)
        assert isinstance(result.recipes[0], RepositoryRecipe)
        assert result.recipes[0].pass_limit == 10


@pytest.mark.parametrize("threshold", ["default", None, 86400, True, -1])
def test_provider_age_configuration(tmp_path, threshold):
    from standalone.evidence_pipeline.collection.public_transport import endpoint

    document = configuration(tmp_path)
    item = document["inputs"][0]
    item["scope"].update(
        source="FIRST", input_kind="epss", scope_reference=endpoint("FIRST")
    )
    if threshold != "default":
        item["provider_age_seconds"] = threshold
    if threshold is True or threshold == -1:
        with pytest.raises(ValueError):
            load(save(tmp_path, document), now=NOW)
    else:
        result = load(save(tmp_path, document), now=NOW)
        if threshold is None:
            assert result.provider_policies == ()
        else:
            assert result.provider_policies[0].max_age_seconds == (
                172800 if threshold == "default" else threshold
            )


def test_absent_configuration_is_empty_off_without_discovering_connections():
    result = load(None, now=NOW)
    assert not result.recipes and not result.state.inputs


@pytest.mark.parametrize("explicit_age", [None, 86400])
def test_archive_epss_has_no_implicit_current_feed_age_policy(tmp_path, explicit_age):
    from standalone.evidence_pipeline.collection.public_transport import endpoint

    document = configuration(tmp_path)
    item = document["inputs"][0]
    item["scope"].update(
        source="FIRST",
        input_kind="epss",
        scope_reference=endpoint("FIRST", score_date="2026-09-12"),
    )
    item["parameters"] = {"score_date": "2026-09-12"}
    if explicit_age is not None:
        item["provider_age_seconds"] = explicit_age
    with pytest.raises(ValueError, match="deferred"):
        load(save(tmp_path, document), now=NOW)


@pytest.mark.parametrize("damage", [None, "route", "network", "limit", "parameter"])
def test_enrichment_configuration_is_bound_to_worker_contract(tmp_path, damage):
    from .enrichment_recipe import EnrichmentRecipe

    document = configuration(tmp_path)
    item = document["inputs"][0]
    item["scope"].update(
        source="NVD",
        input_kind="enrichment_queue",
        scope_reference="triagemate:enrichment/NVD",
    )
    item["parameters"] = {"limit": 1}
    if damage == "route":
        item["scope"]["scope_reference"] += "/other"
    elif damage == "network":
        item["allow_network"] = True
    elif damage == "limit":
        item["parameters"]["limit"] = True
    elif damage == "parameter":
        item["parameters"]["request_url"] = "https://example.invalid"
    if damage:
        with pytest.raises(ValueError):
            load(save(tmp_path, document), now=NOW)
    else:
        result = load(save(tmp_path, document), now=NOW)
        recipe = result.recipes[0]
        assert isinstance(recipe, EnrichmentRecipe)
        assert (
            recipe.binding().worker_contract
            == result.state.definitions[recipe.scope.connection_id].worker_contract
        )


def test_worker_contract_and_schedule_survive_checkpoint(tmp_path):
    document = configuration(tmp_path)
    result = load(save(tmp_path, document), now=NOW)
    definition = next(iter(result.state.definitions.values()))
    assert len(definition.worker_contract) == 64
    assert definition.schedule.offset_seconds == 120
    assert decode(encode(result.state)).definitions == result.state.definitions
    document["inputs"][0]["schedule"] = dict(kind="daily", hour=8, minute=15)
    daily = load(save(tmp_path, document), now=NOW)
    assert (
        next(iter(daily.state.definitions.values())).worker_contract
        == definition.worker_contract
    )
    assert next(iter(daily.state.definitions.values())).schedule.hour == 8


@pytest.mark.parametrize(
    "damage",
    [
        "network",
        "origin",
        "route",
        "relative",
        "unknown",
        "duplicate",
        "boolean_interval",
    ],
)
def test_invalid_or_implicit_input_authority_is_rejected(tmp_path, damage):
    document = configuration(tmp_path)
    item = document["inputs"][0]
    if damage == "network":
        item["allow_network"] = True
    elif damage == "origin":
        item["scope"]["origin"] = "lab"
    elif damage == "route":
        item["scope"]["scope_reference"] = "https://example.invalid/other"
    elif damage == "relative":
        item["bundle_root"] = "bundles"
    elif damage == "unknown":
        item["parameters"] = {"arbitrary_url": "https://example.invalid"}
    elif damage == "duplicate":
        document["inputs"].append(item)
    elif damage == "boolean_interval":
        item["schedule"]["seconds"] = True
    with pytest.raises(ValueError):
        load(save(tmp_path, document), now=NOW)


def test_unsafe_or_missing_named_config_does_not_fall_back_to_empty(tmp_path):
    with pytest.raises(FileNotFoundError):
        load(tmp_path / "missing", now=NOW)
    path = save(tmp_path, configuration(tmp_path))
    path.chmod(0o644)
    with pytest.raises(ValueError):
        load(path, now=NOW)
    path.chmod(0o600)
    link = tmp_path / "symlink"
    link.symlink_to(path)
    with pytest.raises(OSError):
        load(link, now=NOW)
    path.write_text('{"version":1,"version":1}')
    with pytest.raises(ValueError, match="Duplicate"):
        load(path, now=NOW)


@pytest.mark.parametrize(
    "parameters",
    [
        {},
        {"starting_month": None},
        {"starting_month": "2099-Jan", "retained_ids": ["2098-Jan", "2098-Jan"]},
        {"starting_month": "2099-Jan", "retained_ids": "2098-Jan"},
    ],
)
def test_msrc_discovery_rejects_implicit_or_ambiguous_history_range(
    tmp_path, parameters
):
    from .repository_recipe import SOURCE_URLS

    document = configuration(tmp_path)
    item = document["inputs"][0]
    item["scope"].update(
        source="MSRC", input_kind="repository", scope_reference=SOURCE_URLS["MSRC"]
    )
    item["parameters"] = parameters
    with pytest.raises(ValueError):
        load(save(tmp_path, document), now=NOW)


def test_msrc_explicit_all_history_changes_worker_contract(tmp_path):
    from .repository_recipe import SOURCE_URLS

    document = configuration(tmp_path)
    item = document["inputs"][0]
    item["scope"].update(
        source="MSRC", input_kind="repository", scope_reference=SOURCE_URLS["MSRC"]
    )
    item["parameters"] = dict(starting_month="2099-Jan", retained_ids=[])
    recent = load(save(tmp_path, document), now=NOW)
    item["parameters"]["starting_month"] = None
    all_history = load(save(tmp_path, document), now=NOW)
    identity = item["scope"]["connection_id"]
    assert (
        recent.state.definitions[identity].worker_contract
        != all_history.state.definitions[identity].worker_contract
    )
    assert all_history.recipes[0].starting_month is None


def test_oversized_interval_is_rejected_at_configuration_load(tmp_path):
    document = configuration(tmp_path)
    document["inputs"][0]["schedule"]["seconds"] = 86400000000000
    with pytest.raises(ValueError, match="time range"):
        load(save(tmp_path, document), now=NOW)
