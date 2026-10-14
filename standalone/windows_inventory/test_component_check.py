"""Synthetic independent checks; no invented production component mappings."""

from dataclasses import asdict, replace
from datetime import datetime, timezone, timedelta
import hashlib
import json

import pytest

from .component_check import (
    AssemblyIdentity,
    AssemblyObservation,
    CheckContext,
    ComponentIdentity,
    ComponentRule,
    SourceAnchor,
    check_inventory,
)
from .test_contract import BINDING, sample
from .test_manifest import metadata


SOURCE = b"Explicitly synthetic source interpretation for boundary testing only."
DIGEST = hashlib.sha256(SOURCE).hexdigest()
ANCHOR = SourceAnchor(
    DIGEST,
    "https://example.invalid/synthetic-advisory",
    "synthetic product/CVE/fix/conditions",
)


def case(version="1.2.3.4"):
    data = sample()
    item = data["records"][1]
    item.update(version=version, is_bundle=False, manifest=metadata(version=version))
    item["user_states"][0]["install_state"] = "Installed"
    raw = json.dumps(data).encode()
    context = CheckContext(
        BINDING,
        "synthetic",
        hashlib.sha256(raw).hexdigest(),
        datetime(2026, 9, 19, tzinfo=timezone.utc),
        "Windows11",
        "25H2",
        26200,
        "x64",
        ANCHOR,
    )
    rule = ComponentRule(
        "synthetic-rule",
        ComponentIdentity(
            *(item[k] for k in ("name", "family_name", "publisher", "architecture"))
        ),
        "CVE-2026-12345",
        "Synthetic update",
        "25H2",
        26200,
        "x64",
        "1.2.3.1",
        "1.2.3.5",
        "1.2.3.9",
        ANCHOR,
        ANCHOR,
        ANCHOR,
        ANCHOR,
        True,
    )
    return raw, context, rule


def run(raw, context, rules):
    return check_inventory(
        raw,
        binding=BINDING,
        context=context,
        rules=rules,
        retained_sources={DIGEST: SOURCE},
    )


@pytest.mark.parametrize(
    "version,state",
    [
        ("1.2.3.1", "update_required"),
        ("1.2.3.4", "update_required"),
        ("1.2.3.5", "fix_present"),
        ("1.2.3.9", "fix_present"),
        ("1.2.3.10", "unknown"),
        ("1.2.4.0", "unknown"),
        ("1.2.3.0", "unknown"),
        ("01.2.3.4", "unknown"),
    ],
)
def test_closed_source_interval_and_version_namespace(version, state):
    raw, ctx, rule = case(version)
    report = run(raw, ctx, [rule])
    assert report["rows"][1]["evaluations"][0]["state"] == state
    assert report["rows"][1]["state"] == "unknown"
    assert report["defender_coverage"] == "unverified"
    assert report["rows"][0]["reason"] == "outside_appx_component_contract"


@pytest.mark.parametrize(
    "change",
    [
        {"operating_system": "Windows10"},
        {"release": "24H2"},
        {"os_branch": 26100},
        {"os_architecture": "arm64"},
    ],
)
def test_other_os_targets_do_not_inherit_answers(change):
    raw, ctx, rule = case()
    assert (
        run(raw, replace(ctx, **change), [rule])["rows"][1]["evaluations"][0]["state"]
        == "unknown"
    )


def test_no_rules_is_unknown_not_clean_and_no_fuzzy_identity():
    raw, ctx, rule = case()
    assert run(raw, ctx, [])["rows"][1]["reason"] == "no_exact_source_rule"
    for field in ("name", "family_name", "publisher", "architecture"):
        changed = replace(
            rule.component, **{field: "X86" if field == "architecture" else "other"}
        )
        assert (
            run(raw, ctx, [replace(rule, component=changed)])["rows"][1]["evaluations"]
            == []
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"status": "Error"},
        {"is_bundle": True},
        {"is_resource_package": True},
        {"user_states": []},
    ],
)
def test_installation_boundaries(changes):
    raw, ctx, rule = case()
    data = json.loads(raw)
    data["records"][1].update(changes)
    if changes.get("is_bundle") or changes.get("is_resource_package"):
        data["records"][1].pop("manifest")
    raw = json.dumps(data).encode()
    ctx = replace(ctx, inventory_sha256=hashlib.sha256(raw).hexdigest())
    assert run(raw, ctx, [rule])["rows"][1]["evaluations"][0]["state"] == "unknown"


def test_all_source_conditions_are_required():
    raw, ctx, rule = case()
    for changed in (
        replace(rule, conditions_complete=False),
        replace(rule, required_conditions=(("feature", "enabled"),)),
    ):
        assert (
            run(raw, ctx, [changed])["rows"][1]["evaluations"][0]["state"] == "unknown"
        )
    report = run(
        raw,
        replace(ctx, conditions=(("feature", "enabled"),)),
        [replace(rule, required_conditions=(("feature", "enabled"),))],
    )
    assert report["rows"][1]["evaluations"][0]["state"] == "update_required"


def test_conflicting_rules_are_unknown_not_selected_by_date_or_update_number():
    raw, ctx, rule = case()
    other = replace(rule, rule_id="other", first_fixed="1.2.3.3")
    results = run(raw, ctx, [rule, other])["rows"][1]["evaluations"]
    assert {r["reason"] for r in results} == {"conflicting_source_rules"}
    assert {r["state"] for r in results} == {"unknown"}


def test_wrong_binding_hash_time_or_proof_fails_closed():
    raw, ctx, rule = case()
    for changed in (
        replace(
            ctx,
            binding=replace(BINDING, device_id="44444444-4444-4444-8444-444444444444"),
        ),
        replace(ctx, inventory_sha256="0" * 64),
        replace(ctx, observed_at=ctx.observed_at + timedelta(days=1)),
    ):
        with pytest.raises(ValueError):
            run(raw, changed, [rule])
    for proofs in ({}, {DIGEST: b"altered"}):
        with pytest.raises(ValueError, match="retained evidence"):
            check_inventory(
                raw, binding=BINDING, context=ctx, rules=[rule], retained_sources=proofs
            )


@pytest.mark.parametrize(
    "changes",
    [
        {"first_fixed": "1.2.4.0", "last_verified": "1.2.4.9"},
        {"first_fixed": "1.2.3.0"},
        {"conditions_complete": 1},
        {"required_conditions": (("a", "b"), ("a", "c"))},
        {"first_affected": "1.2"},
        {"os_branch": True},
    ],
)
def test_invalid_rule_contracts_rejected(changes):
    _, _, rule = case()
    with pytest.raises(ValueError):
        replace(rule, **changes)


def test_duplicate_rules_and_incomplete_native_inventory_rejected():
    raw, ctx, rule = case()
    with pytest.raises(ValueError, match="Duplicate rule"):
        run(raw, ctx, [rule, rule])
    data = json.loads(raw)
    data["complete"] = False
    with pytest.raises(ValueError, match="complete timed"):
        run(json.dumps(data).encode(), ctx, [rule])


def test_assembly_version_is_never_substituted_by_package_version():
    raw, ctx, rule = case("1.2.3.9")
    identity = AssemblyIdentity(
        "SyntheticAssembly", "amd64", "synthetic-token", "neutral"
    )
    rule = replace(
        rule,
        assembly=identity,
        first_affected="10.0.26200.1",
        first_fixed="10.0.26200.5",
        last_verified="10.0.26200.9",
    )
    item = AssemblyObservation(
        json.loads(raw)["records"][1]["native_id"],
        identity,
        "10.0.26200.4",
        ctx.observed_at,
        True,
        ANCHOR,
    )
    assert (
        run(raw, ctx, [rule])["rows"][1]["evaluations"][0]["reason"]
        == "missing_or_conflicting_active_assembly"
    )
    report = run(raw, replace(ctx, assemblies=(item,)), [rule])
    assert report["rows"][1]["evaluations"][0]["state"] == "update_required"
    for other in (
        replace(item, active_manifest_link=False),
        replace(item, identity=replace(identity, public_key_token="other")),
    ):
        assert (
            run(raw, replace(ctx, assemblies=(other,)), [rule])["rows"][1][
                "evaluations"
            ][0]["state"]
            == "unknown"
        )
    assert (
        run(
            raw,
            replace(ctx, assemblies=(item, replace(item, version="10.0.26200.6"))),
            [rule],
        )["rows"][1]["evaluations"][0]["state"]
        == "unknown"
    )
    for other in (
        replace(item, native_id="other"),
        replace(item, observed_at=ctx.observed_at + timedelta(days=1)),
    ):
        with pytest.raises(ValueError, match="pinned inventory"):
            run(raw, replace(ctx, assemblies=(other,)), [rule])


def files(tmp_path):
    raw, ctx, rule = case()
    inventory = tmp_path / "inventory.json"
    inventory.write_bytes(raw)
    binding = tmp_path / "binding.json"
    binding.write_text(json.dumps(asdict(BINDING)))
    evidence = tmp_path / "evidence.json"
    data = dict(
        contract="triagemate-component-rules-v1",
        context=asdict(ctx),
        rules=[asdict(rule)],
    )
    data["context"]["observed_at"] = ctx.observed_at.isoformat()
    evidence.write_text(json.dumps(data))
    sources = tmp_path / "sources"
    sources.mkdir()
    (sources / DIGEST).write_bytes(SOURCE)
    return dict(
        inventory=inventory, binding=binding, evidence=evidence, sources=sources
    )


def test_file_adapter_retains_provenance_without_network_or_source_mutation(
    tmp_path, monkeypatch, capsys
):
    import socket
    from .component_check_commands import main

    monkeypatch.setattr(socket, "socket", lambda *a, **k: pytest.fail("No network"))
    paths = files(tmp_path)
    before = {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    main([arg for k, v in paths.items() for arg in ("--" + k, str(v))])
    result = json.loads(capsys.readouterr().out)
    assert result["rows"][1]["evaluations"][0]["state"] == "update_required"
    assert result["rules"][0]["fix_source"]["sha256"] == DIGEST
    assert all(p.read_bytes() == data for p, data in before.items())


def test_file_adapter_rejects_duplicate_keys_and_symlink_sources(tmp_path):
    from .component_check_commands import evaluate_files, load

    paths = files(tmp_path)
    path = paths["sources"] / DIGEST
    path.unlink()
    outside = tmp_path / "outside"
    outside.write_bytes(SOURCE)
    path.symlink_to(outside)
    with pytest.raises(ValueError, match="nonsymlink"):
        evaluate_files(**paths)
    paths["evidence"].write_text('{"a": 1, "a": 2}')
    with pytest.raises(ValueError, match="Duplicate"):
        load(paths["evidence"])


def test_cli_failure_does_not_print_private_evidence(tmp_path, capsys):
    from .component_check_commands import main

    paths = files(tmp_path)
    paths["evidence"].write_text('{"private": "must-not-be-printed"}')
    with pytest.raises(SystemExit) as error:
        main([arg for k, v in paths.items() for arg in ("--" + k, str(v))])
    output = capsys.readouterr()
    assert error.value.code == 2
    assert not output.out and "must-not-be-printed" not in output.err


def test_registration_without_manifest_cannot_claim_fix():
    raw, ctx, rule = case("1.2.3.9")
    data = json.loads(raw)
    data["records"][1].pop("manifest")
    raw = json.dumps(data).encode()
    ctx = replace(ctx, inventory_sha256=hashlib.sha256(raw).hexdigest())
    result = run(raw, ctx, [rule])["rows"][1]["evaluations"][0]
    assert result["state"] == "unknown"
    assert result["reason"] == "active_package_manifest_unverified"


def test_special_files_rejected_without_blocking(tmp_path):
    import os
    from .component_check_commands import read_regular

    pipe = tmp_path / "pipe"
    os.mkfifo(pipe)
    with pytest.raises(ValueError, match="Regular"):
        read_regular(pipe)


@pytest.mark.parametrize(
    "field,value",
    [
        ("name", "Synthetic app.1.6"),
        ("version", "6.0.0.1"),
        ("publisher", "CN=Different synthetic publisher"),
    ],
)
def test_conflicting_manifest_cannot_borrow_registration_applicability(field, value):
    raw, ctx, rule = case("1.2.3.9")
    data = json.loads(raw)
    data["records"][1]["manifest"][field] = value
    raw = json.dumps(data).encode()
    ctx = replace(ctx, inventory_sha256=hashlib.sha256(raw).hexdigest())
    with pytest.raises(ValueError, match="Manifest identity differs"):
        run(raw, ctx, [rule])


def test_disclosed_manifest_identity_conflict_remains_unknown():
    raw, ctx, rule = case("1.2.3.9")
    data = json.loads(raw)
    value = data["records"][1]["manifest"]
    for field in (
        "sha256",
        "name",
        "version",
        "publisher",
        "display_name_reference",
        "display_name",
        "publisher_display_name",
        "resource_lookup_hresult",
    ):
        value[field] = None
    value.update(
        state="unavailable",
        reason="manifest_identity_conflict",
        display_name_basis="unresolved",
    )
    raw = json.dumps(data).encode()
    ctx = replace(ctx, inventory_sha256=hashlib.sha256(raw).hexdigest())
    result = run(raw, ctx, [rule])["rows"][1]["evaluations"][0]
    assert result["state"] == "unknown"
    assert result["reason"] == "active_package_manifest_unverified"
