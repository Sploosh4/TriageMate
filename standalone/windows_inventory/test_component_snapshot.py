"""Synthetic selected-component evidence, including failure and identity boundaries."""

from dataclasses import replace
import base64
import hashlib
import json

import pytest

from .component_check import check_selected_components
from .component_snapshot import validate_selected
from .test_component_check import case, DIGEST, SOURCE
from .test_contract import BINDING


def encoded(raw):
    return base64.b64encode(raw).decode(), hashlib.sha256(raw).hexdigest()


def sample_selected():
    inventory, _, rule = case()
    record = json.loads(inventory)["records"][1]
    xml = (
        '<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"><Identity Name="'
        + record["name"]
        + '" Version="'
        + record["version"]
        + '" Publisher="'
        + record["publisher"]
        + '" ProcessorArchitecture="'
        + record["architecture"].lower()
        + '"/></Package>'
    ).encode()
    payload, digest = encoded(xml)
    row = {
        k: record[k]
        for k in (
            "name",
            "native_id",
            "version",
            "family_name",
            "publisher",
            "architecture",
            "status",
            "is_framework",
            "is_resource_package",
            "is_bundle",
            "user_states",
        )
    }
    row.update(
        state="observed",
        observed_at="2026-09-19T00:00:00Z",
        manifest={
            "path": r"C:\Windows\SystemApps\Synthetic\AppxManifest.xml",
            "base64": payload,
            "sha256": digest,
            "hardlinks": [r"\Windows\WinSxS\synthetic_assembly\AppxManifest.xml"],
        },
        assemblies=[],
        error_code=None,
    )
    value = dict(
        contract="triagemate-windows-component-observations-v1",
        started_at=row["observed_at"],
        finished_at=row["observed_at"],
        machine_guid=BINDING.machine_guid,
        tenant_id=BINDING.tenant_id,
        device_id=BINDING.device_id,
        requested_names=[row["name"]],
        os=dict(
            caption="Microsoft Windows 11 Education",
            release="25H2",
            build="26200",
            ubr=1,
            architecture="AMD64",
        ),
        dictionary=None,
        rows=[row],
        complete=True,
        scope="Synthetic selected observation",
    )
    return value, rule


def check(value, rules=()):
    return check_selected_components(
        json.dumps(value).encode(),
        binding=BINDING,
        origin="synthetic",
        rules=rules,
        retained_sources={DIGEST: SOURCE},
    )


def test_selected_observation_uses_exact_native_os_and_retained_manifest():
    value, rule = sample_selected()
    result = check(value, [rule])
    assert result["rows"][0]["evaluations"][0]["state"] == "update_required"
    assert result["rows"][0]["state"] == "unknown"
    assert result["defender_coverage"] == "unverified"
    assert result["input_contract"] == value["contract"]
    assert len(result["rows"]) == 1


@pytest.mark.parametrize(
    "mutation",
    [
        lambda v: v.update(machine_guid="11111111-1111-1111-1111-111111111111"),
        lambda v: v.update(complete=False),
        lambda v: v["rows"][0].update(observed_at="2026-09-18T00:00:00Z"),
        lambda v: v["rows"][0]["manifest"].update(sha256="0" * 64),
        lambda v: v["rows"].append(v["rows"][0]),
        lambda v: v["requested_names"].append("missing"),
        lambda v: v["rows"][0].update(is_bundle=0),
        lambda v: v["rows"][0].update(error_code="invented"),
        lambda v: v.update(rows=[]),
    ],
)
def test_rejects_unbound_incomplete_or_altered_observations(mutation):
    value, _ = sample_selected()
    mutation(value)
    with pytest.raises(ValueError):
        check(value)


@pytest.mark.parametrize("field", ["name", "version", "publisher"])
def test_conflicting_manifest_identity_cannot_produce_applicability(field):
    value, rule = sample_selected()
    row = value["rows"][0]
    row[field] = {"name": "Different", "version": "1.2.3.8", "publisher": "Other"}[
        field
    ]
    value["requested_names"] = [row["name"]]
    component = (
        replace(rule.component, **{field: row[field]})
        if field != "version"
        else rule.component
    )
    result = check(value, [replace(rule, component=component)])
    assert (
        result["rows"][0]["evaluations"][0]["reason"]
        == "active_package_manifest_unverified"
    )


def test_unavailable_manifest_and_absent_component_are_separate():
    value, rule = sample_selected()
    value["rows"][0].update(manifest=None, error_code="component_evidence_unavailable")
    value["requested_names"].append("NotPresent")
    value["rows"].append(
        dict(name="NotPresent", state="not_observed", observed_at=value["started_at"])
    )
    result = check(value, [rule])
    assert result["not_observed"] == ["NotPresent"]
    assert result["rows"][0]["evaluations"][0]["state"] == "unknown"


def test_conflicting_missing_and_present_rows_rejected():
    value, _ = sample_selected()
    value["rows"].append(
        dict(
            name=value["requested_names"][0],
            state="not_observed",
            observed_at=value["started_at"],
        )
    )
    with pytest.raises(ValueError):
        check(value)


def test_unsafe_manifest_rejected_even_with_correct_hash():
    value, _ = sample_selected()
    raw = b'<!DOCTYPE Package [<!ENTITY x "unsafe">]><Package>&x;</Package>'
    payload, digest = encoded(raw)
    value["rows"][0]["manifest"].update(base64=payload, sha256=digest)
    with pytest.raises(ValueError):
        check(value)


def assembly(value):
    raw = b'<assembly xmlns="urn:schemas-microsoft-com:asm.v3" manifestVersion="1.0"><assemblyIdentity name="synthetic" version="1.2.3.4" processorArchitecture="amd64" publicKeyToken="synthetic" language="neutral"/></assembly>'
    payload, digest = encoded(raw)
    entry = dict(
        path=r"C:\Windows\WinSxS\Manifests\synthetic_assembly.manifest",
        active_hardlink=value["rows"][0]["manifest"]["hardlinks"][0],
        source_sha256=digest,
        decoded_sha256=digest,
        decoded_base64=payload,
        observed_at=value["started_at"],
    )
    value["rows"][0]["assemblies"] = [entry]
    return entry


def test_decoded_manifest_and_missing_compressed_bytes_remain_distinct():
    value, _ = sample_selected()
    entry = assembly(value)
    assert check(value)["compressed_source_bytes_complete"] is False
    entry["source_base64"] = entry["decoded_base64"]
    assert check(value)["compressed_source_bytes_complete"] is True


@pytest.mark.parametrize(
    "mutation",
    [
        lambda e: e.update(path=r"C:\Windows\WinSxS\Manifests\unrelated.manifest"),
        lambda e: e.update(active_hardlink=r"\Windows\WinSxS\other\AppxManifest.xml"),
        lambda e: e.update(decoded_sha256="0" * 64),
        lambda e: e.update(observed_at="2026-09-18T00:00:00Z"),
        lambda e: e.update(source_base64="invalid"),
    ],
)
def test_assembly_requires_same_link_bytes_and_window(mutation):
    value, _ = sample_selected()
    mutation(assembly(value))
    with pytest.raises(ValueError):
        check(value)


def test_duplicate_json_keys_rejected():
    value, _ = sample_selected()
    raw = (
        json.dumps(value)
        .replace('"complete": true', '"complete": true, "complete": true')
        .encode()
    )
    with pytest.raises(ValueError):
        validate_selected(raw, BINDING)


def test_collector_failure_cannot_reuse_readable_manifest_as_success():
    value, rule = sample_selected()
    value["rows"][0]["error_code"] = "package_changed_during_collection"
    result = check(value, [rule])
    assert (
        result["rows"][0]["evaluations"][0]["reason"]
        == "active_package_manifest_unverified"
    )


def test_os_target_and_uncollected_conditions_are_not_inferred():
    value, rule = sample_selected()
    value["os"]["caption"] = "Microsoft Windows Server 2025 Standard"
    assert check(value, [rule])["rows"][0]["evaluations"][0]["state"] == "unknown"
    value, rule = sample_selected()
    rule = replace(rule, required_conditions=(("feature_enabled", "yes"),))
    assert (
        check(value, [rule])["rows"][0]["evaluations"][0]["reason"]
        == "required_condition_missing_or_different"
    )


def test_selected_fixed_rule_remains_per_cve_not_overall():
    value, rule = sample_selected()
    rule = replace(rule, first_fixed="1.2.3.4")
    result = check(value, [rule])
    assert result["rows"][0]["evaluations"][0]["state"] == "fix_present"
    assert result["rows"][0]["state"] == "unknown"
    assert result["defender_coverage"] == "unverified"


@pytest.mark.parametrize("architecture", [None, "arm64"])
def test_missing_or_conflicting_manifest_architecture_never_establishes_fix(
    architecture,
):
    value, rule = sample_selected()
    manifest = value["rows"][0]["manifest"]
    raw = base64.b64decode(manifest["base64"])
    current = value["rows"][0]["architecture"].lower()
    old = (' ProcessorArchitecture="' + current + '"').encode()
    replacement = (
        b""
        if architecture is None
        else (' ProcessorArchitecture="' + architecture + '"').encode()
    )
    manifest["base64"], manifest["sha256"] = encoded(raw.replace(old, replacement))
    result = check(value, [replace(rule, first_fixed="1.2.3.4")])
    assert result["rows"][0]["evaluations"][0]["state"] == "unknown"
    reason = result["rows"][0]["evaluations"][0]["reason"]
    assert reason == (
        "active_manifest_architecture_unverified"
        if architecture is None
        else "active_package_manifest_unverified"
    )


def selected_files(tmp_path):
    from dataclasses import asdict

    value, rule = sample_selected()
    paths = {
        key: tmp_path / key for key in ("selected", "binding", "evidence", "sources")
    }
    paths["selected"].write_text(json.dumps(value))
    paths["binding"].write_text(json.dumps(asdict(BINDING)))
    paths["evidence"].write_text(
        json.dumps(
            dict(
                contract="triagemate-selected-component-rules-v1",
                origin="synthetic",
                rules=[asdict(rule)],
            )
        )
    )
    paths["sources"].mkdir()
    (paths["sources"] / DIGEST).write_bytes(SOURCE)
    return paths


def test_selected_cli_offline_provenance_and_unchanged_inputs(
    tmp_path, monkeypatch, capsys
):
    import socket
    from .component_check_commands import main

    paths = selected_files(tmp_path)
    before = {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    monkeypatch.setattr(socket, "socket", lambda *a, **k: pytest.fail("No network"))
    main([arg for key, path in paths.items() for arg in ("--" + key, str(path))])
    result = json.loads(capsys.readouterr().out)
    assert result["rows"][0]["evaluations"][0]["state"] == "update_required"
    assert result["rows"][0]["state"] == "unknown"
    assert result["defender_coverage"] == "unverified"
    assert result["rules"][0]["fix_source"]["sha256"] == DIGEST
    assert all(p.read_bytes() == raw for p, raw in before.items())


@pytest.mark.parametrize(
    "failure", ["binding", "contract", "context", "hash", "origin", "symlink"]
)
def test_selected_cli_rejects_invalid_evidence_without_disclosure(
    tmp_path, capsys, failure
):
    from .component_check_commands import main

    paths = selected_files(tmp_path)
    if failure == "binding":
        data = json.loads(paths["binding"].read_text())
        data["device_id"] = "private-wrong-device"
        paths["binding"].write_text(json.dumps(data))
    elif failure in ("contract", "context", "origin"):
        data = json.loads(paths["evidence"].read_text())
        data[failure] = "private-invalid-value"
        paths["evidence"].write_text(json.dumps(data))
    elif failure == "hash":
        (paths["sources"] / DIGEST).write_bytes(b"private-modified-source")
    else:
        path = paths["sources"] / DIGEST
        path.unlink()
        outside = tmp_path / "private-source"
        outside.write_bytes(SOURCE)
        path.symlink_to(outside)
    with pytest.raises(SystemExit) as error:
        main([arg for key, path in paths.items() for arg in ("--" + key, str(path))])
    output = capsys.readouterr()
    assert error.value.code == 2
    assert not output.out and "private-" not in output.err
