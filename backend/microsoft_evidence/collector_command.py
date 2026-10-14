"""Explicit lab Microsoft collector; network requires --allow-network.

Configuration contains public policy and local credential paths, never key bytes.
Existing execution bundles replay without acquiring tokens, even with network allowed.
"""

import argparse
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import json
from pathlib import Path
from urllib.parse import quote

import httpx

from standalone.evidence_pipeline.contracts import SourceScope, Snapshot, identifier
from standalone.evidence_pipeline.collection.snapshot_bundle import prepare
from standalone.evidence_pipeline.commands import ingest, ingest_exposure
from .assessment_pipeline import INPUTS as ASSESSMENT_INPUTS
from .catalogue_pipeline import (
    collect_catalogue,
    INPUT_ID as CATALOGUE_INPUT,
    catalogue_path,
)
from standalone.evidence_pipeline.commands import ingest_catalogue
from .certificate_credentials import LocalCertificateResolver, _read_file
from .cloud import (
    MicrosoftEndpointPolicy,
    MicrosoftPermissionManifest,
    prepare_server_owned_collection_context,
    _canonical_sha256,
)
from .live_authority import MicrosoftLiveAuthorityError
from .pipeline import (
    DEVICE_INPUTS,
    connection_scope,
    collect_devices,
    collect_findings,
    finding_binding,
    device_binding,
    collect_and_ingest_software,
    selected_device_id,
    selected_device_allowlist,
)
from .recommendation_pipeline import (
    collect_recommendations,
    collect_and_ingest_recommendations,
    PATH as RECOMMENDATION_PATH,
    device_recommendations_path,
    DEVICE_PATH as RECOMMENDATION_DEVICE_PATH,
    INPUT_ID as RECOMMENDATION_INPUT,
    DEVICE_INPUT_ID as RECOMMENDATION_DEVICE_INPUT,
)
from .software_pipeline import (
    collect_software,
    selected_software_device_id,
    device_software_path,
)
from .missing_patch_pipeline import collect_missing_patches
from .antivirus_pipeline import (
    collect_antivirus,
    INPUT_ID as ANTIVIRUS_INPUT,
    PATH as ANTIVIRUS_PATH,
)
from .update_report_pipeline import collect_update_status, policy_id
from .intune_report_transport import HttpIntuneUpdateReportTransport
from .resource_authority import acquire_resource_token
from .source_registry import SOURCE_INPUTS
from .transport import MicrosoftHttpTransport, MicrosoftTransportError

MISSING_PATCH_PATH = "/api/machines/{machineId}/getmissingkbs"

APP_PATH = "/v1.0/deviceManagement/detectedApps"
EDGE_PATH = APP_PATH + "/{detectedApp-id}/managedDevices"


@dataclass(frozen=True)
class Configuration:
    scope: SourceScope
    endpoint: MicrosoftEndpointPolicy
    manifest: MicrosoftPermissionManifest
    key_path: Path
    certificate_path: Path
    bundle_root: Path

    def prepared(self, now):
        return prepare_server_owned_collection_context(
            scope=connection_scope(self.scope),
            endpoint=self.endpoint,
            manifest=self.manifest,
            now=now,
        )


def load_configuration(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate configuration field")
            result[key] = value
        return result

    value = json.loads(_read_file(path, private=True), object_pairs_hook=unique)
    if not isinstance(value, dict) or set(value) != {
        "scope",
        "endpoint",
        "manifest",
        "key_path",
        "certificate_path",
        "bundle_root",
    }:
        raise ValueError("Invalid collector configuration fields")
    scope = SourceScope(**value["scope"])
    selected_id = selected_device_id(scope)
    selected_device_allowlist(scope)
    if (
        scope.origin != "lab"
        or (
            scope.input_kind != "devices"
            and (scope.source, scope.input_kind)
            not in (
                ("Defender", "findings"),
                ("Defender", "missing_patches"),
                ("Defender", "antivirus"),
                ("Defender", "vulnerability_catalogue"),
                ("Defender", "recommendations"),
                ("Defender", "vulnerability_baseline"),
                ("Defender", "vulnerability_events"),
                ("Intune", "software"),
                ("Intune", "update_status"),
            )
        )
        or scope.source not in DEVICE_INPUTS
    ):
        raise ValueError(
            "Collector supports lab Microsoft devices, Intune software/status and Defender findings/missing patches/antivirus/catalogue"
        )
    endpoint = MicrosoftEndpointPolicy.model_validate(value["endpoint"])
    if (
        selected_id is not None
        and scope.source != "Intune"
        and scope.input_kind != "recommendations"
        and "$filter" not in endpoint.allowed_query_parameter_names
    ):
        raise ValueError("Single-device endpoint must permit its exact filter")
    manifest = MicrosoftPermissionManifest.model_validate(value["manifest"])
    product, input_id, path = DEVICE_INPUTS[scope.source]
    if scope.source == "Intune" and selected_id is not None:
        path += "/" + selected_id
    if scope.input_kind in ASSESSMENT_INPUTS:
        input_id, path = ASSESSMENT_INPUTS[scope.input_kind]
    elif scope.input_kind == "findings":
        input_id, path = (
            "ms-defender-machine-cve-v1",
            "/api/vulnerabilities/machinesVulnerabilities",
        )
    elif scope.input_kind == "missing_patches":
        input_id, path = "ms-defender-missing-kb-v1", MISSING_PATCH_PATH
    elif scope.input_kind == "vulnerability_catalogue":
        input_id, path = CATALOGUE_INPUT, catalogue_path(scope)
    elif scope.input_kind == "antivirus":
        input_id, path = ANTIVIRUS_INPUT, ANTIVIRUS_PATH
    elif scope.input_kind == "update_status":
        policy_id(scope)
        input_id, path = (
            "ms-intune-quality-update-status-v1",
            "/beta/deviceManagement/reports/exportJobs",
        )
    elif scope.input_kind == "recommendations":
        input_id, path = (
            (RECOMMENDATION_DEVICE_INPUT, RECOMMENDATION_DEVICE_PATH)
            if endpoint.path_template == RECOMMENDATION_DEVICE_PATH
            else (RECOMMENDATION_INPUT, RECOMMENDATION_PATH)
        )
        if selected_id is not None:
            input_id, path = (
                RECOMMENDATION_INPUT,
                device_recommendations_path(selected_id),
            )
    elif scope.input_kind == "software":
        software_device = selected_software_device_id(scope)
        input_id, path = (
            ("ms-intune-detected-app-device-edge-v1", EDGE_PATH)
            if endpoint.path_template == EDGE_PATH
            else ("ms-intune-detected-app-v1", APP_PATH)
        )
        if software_device is not None:
            input_id, path = (
                "ms-intune-detected-app-v1",
                device_software_path(software_device),
            )
    host = (
        "api.security.microsoft.com" if product == "defender" else "graph.microsoft.com"
    )
    # Defender can require its legacy OAuth resource even on the current API host.
    audiences = {"https://" + host}
    if product == "defender":
        audiences.add("https://api.securitycenter.microsoft.com")
    source = next(item for item in SOURCE_INPUTS if item.input_id == input_id)
    expected_permissions = source.application_permissions
    if scope.input_kind == "update_status" and ":group:" in scope.scope_reference:
        # The pinned lab policy additionally checks its sole group member before
        # each export. Legacy policy-only manifests remain usable for replay.
        expected_permissions = tuple(
            sorted({*expected_permissions, "Device.Read.All", "GroupMember.Read.All"})
        )
    if (
        endpoint.cloud != "global"
        or endpoint.product != product
        or endpoint.host != host
        or endpoint.path_template != path
        or endpoint.token_audience not in audiences
        or endpoint.classification != "live"
        or manifest.classification != "live"
        or manifest.scope != connection_scope(scope)
        or tuple(grant.role for grant in manifest.grants) != expected_permissions
    ):
        raise ValueError("Configuration differs from the fixed collection policy")
    paths = [
        Path(value[key]) for key in ("key_path", "certificate_path", "bundle_root")
    ]
    if any(not path.is_absolute() for path in paths):
        raise ValueError("Collector paths must be absolute")
    repository = Path(__file__).resolve().parents[2]
    local_work = repository / "ui-engine" / "work"
    for path in paths:
        resolved = path.resolve()
        if resolved.is_relative_to(repository) and not resolved.is_relative_to(
            local_work
        ):
            raise ValueError(
                "Credential and collection paths must stay outside repository source files"
            )
    return Configuration(scope, endpoint, manifest, *paths)


def run(
    config,
    execution_id,
    *,
    allow_network=False,
    device_snapshot=None,
    association_config=None,
    predecessor=None,
    since=None,
    now=lambda: datetime.now(timezone.utc),
):
    execution_id = identifier(execution_id)
    if config.scope.input_kind in ASSESSMENT_INPUTS:
        if association_config is not None:
            raise ValueError("Assessment does not use software associations")
        return run_assessment(
            config,
            execution_id,
            device_snapshot,
            predecessor,
            since,
            allow_network,
            now,
        )
    if predecessor is not None or since is not None:
        raise ValueError("Checkpoint arguments require assessment collection")
    if config.scope.input_kind in ("software", "recommendations"):
        return run_associated(
            config,
            execution_id,
            device_snapshot=device_snapshot,
            association_config=association_config,
            allow_network=allow_network,
            now=now,
        )
    if association_config is not None:
        raise ValueError(
            "Association configuration requires software or recommendations"
        )
    binding = None
    if config.scope.input_kind == "findings":
        if device_snapshot is None:
            raise ValueError("Finding collection requires a saved device execution")
        binding = finding_binding(config.scope, device_snapshot)
    elif config.scope.input_kind == "missing_patches":
        if device_snapshot is None:
            raise ValueError("Missing patches require a saved device execution")
        binding = device_binding(config.scope, device_snapshot, source="Defender")
    elif config.scope.input_kind == "antivirus":
        if device_snapshot is None:
            raise ValueError("Antivirus requires a saved device execution")
        binding = device_binding(config.scope, device_snapshot, source="Defender")
    elif config.scope.input_kind == "update_status":
        policy_id(config.scope)
        if device_snapshot is None:
            raise ValueError("Update reports require a saved device execution")
        binding = device_binding(config.scope, device_snapshot, source="Intune")
    elif device_snapshot is not None:
        raise ValueError("Device collection does not accept a device binding")
    if not allow_network and not (config.bundle_root / execution_id).exists():
        raise ValueError("No saved execution; new collection requires --allow-network")

    def collect():
        if not allow_network:
            raise ValueError("Network collection is disabled")
        started = now()
        try:
            if config.scope.input_kind == "update_status":
                from .update_report_pipeline import isolation_group_id

                isolation_group_id(config.scope)
            if config.scope.input_kind == "missing_patches":
                return fetch_missing_patches(config, execution_id, device_snapshot, now)
            prepared = config.prepared(started)
            resolver = LocalCertificateResolver(
                prepared=prepared,
                key_path=config.key_path,
                certificate_path=config.certificate_path,
                now=now,
            )
            with httpx.Client(trust_env=False, follow_redirects=False) as client:
                token = acquire_resource_token(
                    prepared=prepared,
                    credential_resolver=resolver,
                    client=client,
                    now=started,
                )
                if config.scope.input_kind == "update_status":
                    from .policy_isolation import verify_policy_isolation

                    verify_policy_isolation(
                        client=client,
                        prepared=prepared,
                        token=token,
                        scope=config.scope,
                        device_snapshot=device_snapshot,
                        now=now,
                    )
                    return collect_update_status(
                        scope=config.scope,
                        execution_id=execution_id,
                        device_snapshot=device_snapshot,
                        prepared=prepared,
                        transport=HttpIntuneUpdateReportTransport(
                            client=client,
                            prepared=prepared,
                            token=token,
                            now=now,
                        ),
                        now=now,
                    )
                collector = (
                    collect_catalogue
                    if config.scope.input_kind == "vulnerability_catalogue"
                    else collect_antivirus
                    if config.scope.input_kind == "antivirus"
                    else collect_findings
                    if binding is not None
                    else collect_devices
                )
                extra = (
                    {"device_snapshot": device_snapshot} if binding is not None else {}
                )
                return collector(
                    **extra,
                    scope=config.scope,
                    execution_id=execution_id,
                    prepared=prepared,
                    token=token,
                    transport=MicrosoftHttpTransport(client=client, now=now),
                    now=now,
                )
        except (MicrosoftLiveAuthorityError, MicrosoftTransportError) as exc:
            from .failures import failure_code

            error = failure_code(exc)
        except ValueError:
            error = "invalid_microsoft_collection"
        return Snapshot(
            config.scope, execution_id, started, now(), "failure", False, b"", error
        )

    snapshot = prepare(
        config.scope, execution_id, config.bundle_root, collect=collect, binding=binding
    )
    if binding is not None:
        return ingest_exposure(snapshot, device_snapshot.execution_id)
    if config.scope.input_kind == "vulnerability_catalogue":
        return ingest_catalogue(snapshot)
    return ingest(snapshot)


def fetch_missing_patches(config, execution_id, device_snapshot, now):
    """Resolve only routes belonging to the pinned device snapshot."""
    if config.endpoint.path_template != MISSING_PATCH_PATH:
        raise ValueError("Missing patches require the fixed device route template")
    with httpx.Client(trust_env=False, follow_redirects=False) as client:

        def authority(device_id):
            values = config.endpoint.model_dump(
                mode="json", exclude={"endpoint_policy_sha256"}
            )
            values["path_template"] = MISSING_PATCH_PATH.replace(
                "{machineId}", quote(device_id, safe="")
            )
            endpoint = MicrosoftEndpointPolicy(
                **values, endpoint_policy_sha256=_canonical_sha256(values)
            )
            prepared = replace(config, endpoint=endpoint).prepared(now())
            token = acquire_resource_token(
                prepared=prepared,
                credential_resolver=LocalCertificateResolver(
                    prepared=prepared,
                    key_path=config.key_path,
                    certificate_path=config.certificate_path,
                    now=now,
                ),
                client=client,
                now=now(),
            )
            return prepared, token

        return collect_missing_patches(
            scope=config.scope,
            execution_id=execution_id,
            device_snapshot=device_snapshot,
            authority_for_device=authority,
            transport=MicrosoftHttpTransport(client=client, now=now),
            now=now,
        )


def saved_device(config, execution_id):
    execution_id = identifier(execution_id)
    if (
        config.scope.source not in ("Intune", "Defender")
        or config.scope.input_kind != "devices"
    ):
        raise ValueError("Saved binding must be Intune or Defender device evidence")
    if not (config.bundle_root / execution_id).exists():
        raise ValueError("Saved device execution is missing")

    def no_fetch():
        raise ValueError("Device binding cannot trigger collection")

    return prepare(config.scope, execution_id, config.bundle_root, collect=no_fetch)


def run_associated(
    config, execution_id, *, device_snapshot, association_config, allow_network, now
):
    recommendations = config.scope.input_kind == "recommendations"
    scoped_device = (
        selected_device_id(config.scope)
        if recommendations
        else selected_software_device_id(config.scope)
    )
    primary_path = RECOMMENDATION_PATH if recommendations else APP_PATH
    if scoped_device is not None:
        primary_path = (
            device_recommendations_path(scoped_device)
            if recommendations
            else device_software_path(scoped_device)
        )
    edge_path = RECOMMENDATION_DEVICE_PATH if recommendations else EDGE_PATH
    if device_snapshot is None or (
        association_config is None and scoped_device is None
    ):
        raise ValueError(
            "Associated inputs require saved devices and association configuration"
        )
    if (
        config.endpoint.path_template != primary_path
        or (scoped_device is not None and association_config is not None)
        or (
            scoped_device is None
            and (
                association_config.endpoint.path_template != edge_path
                or association_config.scope != config.scope
            )
        )
    ):
        raise ValueError(
            "Associated configurations must bind the same scope and fixed routes"
        )
    if not allow_network and not (config.bundle_root / execution_id).exists():
        raise ValueError("No saved execution; new collection requires --allow-network")

    def collect():
        if not allow_network:
            raise ValueError("New collection requires --allow-network")
        with httpx.Client(trust_env=False, follow_redirects=False) as client:

            def authorize(cfg):
                prepared = cfg.prepared(now())
                token = acquire_resource_token(
                    prepared=prepared,
                    credential_resolver=LocalCertificateResolver(
                        prepared=prepared,
                        key_path=cfg.key_path,
                        certificate_path=cfg.certificate_path,
                        now=now,
                    ),
                    client=client,
                    now=now(),
                )
                return prepared, token

            def edge_authority(app_id):
                # collect_software validates the route-safe identifier first.
                values = association_config.endpoint.model_dump(
                    mode="json", exclude={"endpoint_policy_sha256"}
                )
                values["path_template"] = edge_path.replace(
                    "{id}" if recommendations else "{detectedApp-id}", app_id
                )
                endpoint = MicrosoftEndpointPolicy(
                    **values, endpoint_policy_sha256=_canonical_sha256(values)
                )
                return authorize(replace(association_config, endpoint=endpoint))

            prepared, token = authorize(config)
            collector = collect_recommendations if recommendations else collect_software
            authority_argument = (
                "association_authority"
                if recommendations
                else "application_device_authority"
            )
            return collector(
                scope=config.scope,
                execution_id=execution_id,
                device_snapshot=device_snapshot,
                prepared=prepared,
                token=token,
                **{authority_argument: edge_authority},
                transport=MicrosoftHttpTransport(client=client, now=now),
                now=now,
            )

    ingest_pair = (
        collect_and_ingest_recommendations
        if recommendations
        else collect_and_ingest_software
    )
    return ingest_pair(
        scope=config.scope,
        execution_id=execution_id,
        root=config.bundle_root,
        device_snapshot=device_snapshot,
        collect=collect,
        now=now,
    )


def run_assessment(
    config, execution_id, device, predecessor, since, allow_network, now
):
    from .assessment_pipeline import collect_assessments, prepare_assessments
    from standalone.evidence_pipeline.assessment_commands import ingest

    if device is None:
        raise ValueError("Assessment requires saved device evidence")
    if config.scope.input_kind == "vulnerability_events" and predecessor is None:
        raise ValueError("Delta requires a committed predecessor")
    if not allow_network and not (config.bundle_root / execution_id).exists():
        raise ValueError("New collection requires --allow-network")

    def fetch():
        if not allow_network:
            raise ValueError("Network collection disabled")
        prepared = config.prepared(now())
        with httpx.Client(trust_env=False, follow_redirects=False) as client:
            token = acquire_resource_token(
                prepared=prepared,
                credential_resolver=LocalCertificateResolver(
                    prepared=prepared,
                    key_path=config.key_path,
                    certificate_path=config.certificate_path,
                    now=now,
                ),
                client=client,
                now=now(),
            )
            return collect_assessments(
                scope=config.scope,
                execution_id=execution_id,
                device_snapshot=device,
                prepared=prepared,
                token=token,
                transport=MicrosoftHttpTransport(client=client, now=now),
                since=since,
                now=now,
            )

    snapshot = prepare_assessments(
        scope=config.scope,
        execution_id=execution_id,
        device_snapshot=device,
        root=config.bundle_root,
        fetch=fetch,
        predecessor=predecessor,
        since=since,
        now=now,
    )
    return ingest(snapshot, device.execution_id, predecessor, since)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--execution-id", required=True)
    parser.add_argument("--allow-network", action="store_true")
    parser.add_argument("--device-config")
    parser.add_argument("--device-execution-id")
    parser.add_argument("--association-config")
    parser.add_argument("--predecessor")
    parser.add_argument("--since")
    args = parser.parse_args(argv)
    try:
        device = None
        if bool(args.device_config) != bool(args.device_execution_id):
            raise ValueError("Both device config and execution ID are required")
        if args.device_config:
            device = saved_device(
                load_configuration(args.device_config), args.device_execution_id
            )
        result = run(
            load_configuration(args.config),
            args.execution_id,
            allow_network=args.allow_network,
            predecessor=args.predecessor,
            since=datetime.fromisoformat(args.since) if args.since else None,
            device_snapshot=device,
            association_config=load_configuration(args.association_config)
            if args.association_config
            else None,
        )
        print(json.dumps(result, sort_keys=True))
        return 0 if result["outcome"] == "success" else 2
    except Exception:
        parser.exit(
            2,
            "Collection/import did not confirm success. Preserve the execution bundle; check configuration and registration before retrying.\n",
        )


if __name__ == "__main__":
    raise SystemExit(main())
