"""Owner-only, explicit local collection configuration; absent config means off."""

from dataclasses import dataclass, replace
from datetime import datetime
import hashlib
import json
from pathlib import Path

from standalone.evidence_pipeline.contracts import SourceScope
from standalone.evidence_pipeline.parsing.public_snapshot import PARSERS
from standalone.evidence_pipeline.collection.public_transport import endpoint
from standalone.evidence_pipeline.parsing.advisory_feeds import SOURCES, validate_scope
from standalone.evidence_pipeline.collection.snapshot_bundle import _read

from .checkpoint import keys, timestamp
from .certificates import Certificate
from .credential_metadata import CredentialMetadata
from .dispatch import Definition, Dispatcher, Job
from .process_worker import PublicRecipe
from .microsoft_worker import MicrosoftRecipe, INDEPENDENT, DEPENDENT
from .windows_inventory_worker import WindowsInventoryRecipe
from standalone.windows_inventory.contract import DeviceBinding
from .repository_recipe import RepositoryRecipe
from .enrichment_recipe import EnrichmentRecipe
from .catalog_target_recipe import CatalogTargetRecipe
from .provider_monitor import ProviderPolicy
from .storage_monitor import StoragePolicy
from .scheduling import Daily, Interval


@dataclass(frozen=True)
class Configuration:
    state: Dispatcher
    recipes: tuple[
        PublicRecipe
        | MicrosoftRecipe
        | WindowsInventoryRecipe
        | RepositoryRecipe
        | EnrichmentRecipe
        | CatalogTargetRecipe,
        ...,
    ]
    certificates: tuple[Certificate, ...] = ()
    provider_policies: tuple[ProviderPolicy, ...] = ()
    storage_policy: StoragePolicy | None = None


def unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate operational configuration field")
        result[key] = value
    return result


def load(path, *, now: datetime):
    if path is None:
        return Configuration(Dispatcher([], now=now), ())
    # A named missing/invalid file is an error, never an empty configuration.
    document = json.loads(_read(Path(path), 1_000_000), object_pairs_hook=unique_fields)
    keys(
        document,
        ["version", "concurrency", "grace_seconds", "inputs"]
        + (
            ["certificates"]
            if isinstance(document, dict) and "certificates" in document
            else []
        )
        + (
            ["credential_metadata"]
            if isinstance(document, dict) and "credential_metadata" in document
            else []
        )
        + (["storage"] if isinstance(document, dict) and "storage" in document else []),
    )
    if type(document["version"]) is not int or document["version"] != 1:
        raise ValueError("Unsupported operational configuration version")
    storage_policy = None
    if document.get("storage") is not None:
        storage = document["storage"]
        keys(storage, ["directories", "maximum_bytes"])
        if not isinstance(storage["directories"], list) or any(
            not isinstance(path, str) for path in storage["directories"]
        ):
            raise ValueError("Storage directories must be a list of paths")
        storage_policy = StoragePolicy(
            tuple(Path(path) for path in storage["directories"]),
            storage["maximum_bytes"],
        )
    if not isinstance(document["inputs"], list) or len(document["inputs"]) > 256:
        raise ValueError("Invalid operational input list")
    if (
        type(document["grace_seconds"]) is not int
        or not 0 <= document["grace_seconds"] <= 300
    ):
        raise ValueError(
            "Operational shutdown grace must be between zero and 300 seconds"
        )
    certificates = []
    configured_certificates = document.get("certificates", [])
    if (
        not isinstance(configured_certificates, list)
        or len(configured_certificates) > 32
    ):
        raise ValueError("At most 32 explicit certificate monitors may be configured")
    for item in configured_certificates:
        keys(
            item,
            [
                "reference_id",
                "label",
                "path",
                "origin",
                "provenance",
                "warn_before_seconds",
            ],
        )
        if not isinstance(item["path"], str):
            raise ValueError("Certificate path must be text")
        certificates.append(Certificate(**{**item, "path": Path(item["path"])}))
    metadata = document.get("credential_metadata", [])
    if not isinstance(metadata, list) or len(metadata) > 32:
        raise ValueError("At most 32 credential metadata monitors may be configured")
    for item in metadata:
        keys(
            item,
            [
                "reference_id",
                "label",
                "path",
                "origin",
                "provenance",
                "warn_before_seconds",
            ],
        )
        if not isinstance(item["path"], str):
            raise ValueError("Credential metadata path must be text")
        certificates.append(CredentialMetadata(**{**item, "path": Path(item["path"])}))
    if len({item.reference_id for item in certificates}) != len(certificates):
        raise ValueError("Duplicate certificate monitoring reference")
    definitions, recipes, provider_policies = [], [], []
    for item in document["inputs"]:
        keys(
            item,
            [
                "scope",
                "schedule",
                "bundle_root",
                "synthetic_input",
                "allow_network",
                "parameters",
            ]
            + (
                ["overdue_after_seconds"]
                if isinstance(item, dict) and "overdue_after_seconds" in item
                else []
            )
            + (
                ["provider_age_seconds"]
                if isinstance(item, dict) and "provider_age_seconds" in item
                else []
            ),
        )
        try:
            scope = SourceScope(**item["scope"])
        except (TypeError, AttributeError) as exc:
            raise ValueError("Invalid configured source scope") from exc
        microsoft = (scope.source, scope.input_kind) in INDEPENDENT | DEPENDENT
        windows_inventory = scope.source == "Windows inventory"
        repository = scope.input_kind in {"repository", "catalog_search"}
        enrichment = scope.input_kind == "enrichment_queue"
        catalog_targets = scope.input_kind == "catalog_targets"
        if (
            not microsoft
            and not windows_inventory
            and not repository
            and not enrichment
            and not catalog_targets
            and (scope.source, scope.input_kind) not in PARSERS
        ):
            raise ValueError("Unsupported configured public input")
        schedule = item["schedule"]
        if not isinstance(schedule, dict):
            raise ValueError("Invalid configured schedule")
        if schedule.get("kind") == "daily":
            keys(schedule, ["kind", "hour", "minute"])
            cadence = Daily(schedule["hour"], schedule["minute"])
        elif schedule.get("kind") == "interval":
            keys(schedule, ["kind", "seconds", "anchor", "offset_seconds"])
            cadence = Interval(
                schedule["seconds"],
                timestamp(schedule["anchor"]),
                schedule["offset_seconds"],
            )
        else:
            raise ValueError("Unknown configured schedule")
        for key in ("bundle_root", "synthetic_input"):
            value = item[key]
            if key == "synthetic_input" and value is None:
                continue
            if not isinstance(value, str) or not Path(value).is_absolute():
                raise ValueError("Operational storage paths must be absolute")
        parameters = item["parameters"]
        if not isinstance(parameters, dict):
            raise ValueError("Invalid public collection parameters")
        dependencies = ()
        if catalog_targets:
            if set(parameters) - {
                "missing_patch_inputs",
                "target_limit",
                "record_limit",
                "pass_limit",
            }:
                raise ValueError("Unknown Catalog target parameter")
            selected = parameters.get("missing_patch_inputs")
            if (
                not isinstance(selected, list)
                or not selected
                or any(not isinstance(key, str) for key in selected)
            ):
                raise ValueError("Explicit missing-patch input list required")
            dependencies = tuple(selected)
            for dependency in dependencies:
                matches = [
                    entry
                    for entry in document["inputs"]
                    if entry.get("scope", {}).get("connection_id") == dependency
                ]
                if len(matches) != 1:
                    raise ValueError(
                        "Catalog target prerequisite must identify one configured input"
                    )
                parent = SourceScope(**matches[0]["scope"])
                if (parent.source, parent.input_kind, parent.origin) != (
                    "Defender",
                    "missing_patches",
                    scope.origin,
                ):
                    raise ValueError(
                        "Catalog targets require same-origin missing-patch inputs"
                    )
            recipe = CatalogTargetRecipe(
                scope,
                Path(item["bundle_root"]),
                dependencies,
                Path(item["synthetic_input"])
                if item["synthetic_input"] is not None
                else None,
                item["allow_network"],
                **{
                    key: value
                    for key, value in parameters.items()
                    if key != "missing_patch_inputs"
                },
            )
            recipe.validate(
                Job(
                    scope.connection_id,
                    scope.connection_id,
                    now,
                    now,
                    tuple((key, key) for key in dependencies),
                )
            )
        elif enrichment:
            if set(parameters) - {"limit", "refresh_completed"}:
                raise ValueError("Unknown enrichment collection parameter")
            recipe = EnrichmentRecipe(
                scope,
                Path(item["bundle_root"]),
                Path(item["synthetic_input"])
                if item["synthetic_input"] is not None
                else None,
                item["allow_network"],
                **parameters,
            )
            recipe.validate(Job(scope.connection_id, scope.connection_id, now, now, ()))
        elif repository:
            allowed = {"record_limit", "pass_limit"}
            if scope.source == "Microsoft Update Catalog":
                allowed.add("kb")
                parameters = {"record_limit": 10, "pass_limit": 10, **parameters}
            elif scope.source == "MSRC":
                allowed.update({"starting_month", "retained_ids"})
                if not {"starting_month", "retained_ids"} <= set(parameters):
                    raise ValueError(
                        "MSRC discovery requires an explicit publication range"
                    )
                retained = parameters["retained_ids"]
                if (
                    not isinstance(retained, list)
                    or any(not isinstance(v, str) for v in retained)
                    or len(set(retained)) != len(retained)
                ):
                    raise ValueError("MSRC retained publications require a unique list")
                parameters = {**parameters, "retained_ids": frozenset(retained)}
            elif scope.source not in {"Red Hat", "Cisco"}:
                allowed.add("metadata_limit")
            if set(parameters) - allowed:
                raise ValueError("Unknown repository collection parameter")
            recipe = RepositoryRecipe(
                scope,
                Path(item["bundle_root"]),
                Path(item["synthetic_input"])
                if item["synthetic_input"] is not None
                else None,
                item["allow_network"],
                **parameters,
            )
            recipe.validate(Job(scope.connection_id, scope.connection_id, now, now, ()))
        elif windows_inventory:
            required = {"device_input", "binding", "native_device_id"}
            if not required <= set(parameters) or set(parameters) - required - {
                "ssh_config",
                "ssh_host",
                "timeout_seconds",
            }:
                raise ValueError("Invalid Windows inventory collection parameters")
            matching = [
                entry
                for entry in document["inputs"]
                if entry.get("scope", {}).get("connection_id")
                == parameters["device_input"]
            ]
            if len(matching) != 1:
                raise ValueError(
                    "Windows inventory requires one configured device prerequisite"
                )
            try:
                binding = DeviceBinding(**parameters["binding"])
            except (TypeError, AttributeError) as exc:
                raise ValueError("Invalid Windows inventory device binding") from exc
            parent = SourceScope(**matching[0]["scope"])
            dependencies = (parent.connection_id,)
            network = item["allow_network"]
            if type(network) is not bool or network != (scope.origin == "lab"):
                raise ValueError(
                    "Windows inventory network authority differs from origin"
                )
            ssh_config = parameters.get("ssh_config")
            if ssh_config is not None and not isinstance(ssh_config, str):
                raise ValueError(
                    "Windows inventory SSH configuration path must be text"
                )
            ssh_path = Path(ssh_config) if ssh_config is not None else None
            recipe = WindowsInventoryRecipe(
                scope,
                Path(item["bundle_root"]),
                parent,
                Path(matching[0]["bundle_root"]),
                binding,
                parameters["native_device_id"],
                Path(item["synthetic_input"])
                if item["synthetic_input"] is not None
                else None,
                ssh_path,
                parameters.get("ssh_host"),
                hashlib.sha256(_read(ssh_path, 131072)).hexdigest()
                if ssh_path is not None
                else None,
                parameters.get("timeout_seconds", 300),
            )
            recipe.validate(
                Job(
                    scope.connection_id,
                    scope.connection_id,
                    now,
                    now,
                    ((parent.connection_id, parent.connection_id),),
                )
            )
        elif microsoft:
            if set(parameters) - {
                "device_input",
                "association_input",
                "baseline_input",
                "collector_config",
                "association_config",
            }:
                raise ValueError("Unknown Microsoft collection parameter")
            network_config = association_config = network_fingerprint = None
            if item["allow_network"] is True:
                from .microsoft_network import fingerprint as configuration_fingerprint

                if (
                    item["synthetic_input"] is not None
                    or "association_input" in parameters
                ):
                    raise ValueError(
                        "Network Microsoft input cannot contain synthetic fixtures"
                    )
                for name in ("collector_config", "association_config"):
                    if name in parameters and not isinstance(parameters[name], str):
                        raise ValueError("Microsoft configuration path must be text")
                if "collector_config" not in parameters:
                    raise ValueError(
                        "Network Microsoft input requires explicit collector configuration"
                    )
                network_config = Path(parameters["collector_config"])
                association_config = (
                    Path(parameters["association_config"])
                    if "association_config" in parameters
                    else None
                )
                network_fingerprint = configuration_fingerprint(
                    network_config, association_config
                )
            elif (
                item["allow_network"] is not False
                or item["synthetic_input"] is None
                or "collector_config" in parameters
                or "association_config" in parameters
            ):
                raise ValueError(
                    "Synthetic Microsoft input requires fixtures without network configuration"
                )
            device_scope = device_root = None
            if "device_input" in parameters:
                matching = [
                    entry
                    for entry in document["inputs"]
                    if entry.get("scope", {}).get("connection_id")
                    == parameters["device_input"]
                ]
                if len(matching) != 1:
                    raise ValueError(
                        "Microsoft device prerequisite must identify one configured input"
                    )
                device_scope = SourceScope(**matching[0]["scope"])
                device_root = Path(matching[0]["bundle_root"])
                dependencies = (device_scope.connection_id,)
            baseline_scope = None
            if "baseline_input" in parameters:
                matching = [
                    entry
                    for entry in document["inputs"]
                    if entry.get("scope", {}).get("connection_id")
                    == parameters["baseline_input"]
                ]
                if len(matching) != 1 or matching[0].get("parameters", {}).get(
                    "device_input"
                ) != parameters.get("device_input"):
                    raise ValueError(
                        "Delta baseline must use the same configured device prerequisite"
                    )
                baseline_scope = SourceScope(**matching[0]["scope"])
                dependencies += (baseline_scope.connection_id,)
            association = parameters.get("association_input")
            if association is not None and not isinstance(association, str):
                raise ValueError("Association fixture must be an absolute path")
            recipe = MicrosoftRecipe(
                scope,
                Path(item["bundle_root"]),
                Path(item["synthetic_input"])
                if item["synthetic_input"] is not None
                else None,
                device_scope,
                device_root,
                Path(association) if association is not None else None,
                baseline_scope,
                network_config,
                association_config,
                network_fingerprint,
            )
            recipe.validate(
                Job(
                    scope.connection_id,
                    scope.connection_id,
                    now,
                    now,
                    tuple((key, key) for key in dependencies),
                )
            )
        else:
            recipe = PublicRecipe(
                scope,
                Path(item["bundle_root"]),
                Path(item["synthetic_input"])
                if item["synthetic_input"] is not None
                else None,
                item["allow_network"],
                tuple(sorted(parameters.items())),
            )
            recipe.validate(Job(scope.connection_id, scope.connection_id, now, now, ()))
            if (scope.source, scope.input_kind) in SOURCES:
                validate_scope(scope)
                if parameters:
                    raise ValueError(
                        "Synthetic vendor configuration has no extra route parameters"
                    )
            elif scope.scope_reference != endpoint(
                scope.source, input_kind=scope.input_kind, **parameters
            ):
                raise ValueError(
                    "Configured source differs from its fixed collection route"
                )
        contract = {
            key: value
            for key, value in item.items()
            if key not in ("schedule", "overdue_after_seconds")
        }
        if (
            isinstance(recipe, WindowsInventoryRecipe)
            and recipe.ssh_config_fingerprint is not None
        ):
            contract["ssh_configuration_fingerprint"] = recipe.ssh_config_fingerprint
        if (
            isinstance(recipe, MicrosoftRecipe)
            and recipe.network_fingerprint is not None
        ):
            contract["microsoft_configuration_sha256"] = recipe.network_fingerprint
        fingerprint = hashlib.sha256(
            json.dumps(contract, sort_keys=True, allow_nan=False).encode()
        ).hexdigest()
        overdue = item.get(
            "overdue_after_seconds",
            2 * (cadence.seconds if isinstance(cadence, Interval) else 86400)
            + document["grace_seconds"],
        )
        if type(overdue) is not int or overdue < 1:
            raise ValueError("Configured overdue threshold must be a positive integer")
        definitions.append(
            Definition(
                scope.connection_id,
                cadence,
                dependencies,
                worker_contract=fingerprint,
                overdue_after_seconds=overdue,
            )
        )
        if isinstance(recipe, (EnrichmentRecipe, CatalogTargetRecipe)):
            recipe = replace(recipe, worker_contract=fingerprint)
        recipes.append(recipe)
        provider_age = item.get(
            "provider_age_seconds",
            172800
            if (scope.source, scope.input_kind) == ("FIRST", "epss")
            and "score_date" not in parameters
            else None,
        )
        if provider_age is not None:
            provider_policies.append(ProviderPolicy(recipe, provider_age))
    return Configuration(
        Dispatcher(
            definitions,
            now=now,
            concurrency=document["concurrency"],
            grace_seconds=document["grace_seconds"],
        ),
        tuple(recipes),
        tuple(certificates),
        tuple(provider_policies),
        storage_policy,
    )
