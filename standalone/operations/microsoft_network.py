"""Reuse the existing Microsoft collector behind explicit, frozen configuration."""

import hashlib
import importlib
from pathlib import Path
import sys

from standalone.evidence_pipeline.collection.snapshot_bundle import _read


def collector():
    # The desktop application executes from the shared source checkout. Its
    # Microsoft package uses backend-local imports, as does the existing CLI.
    backend = str(Path(__file__).resolve().parents[2] / "backend")
    if backend not in sys.path:
        sys.path.insert(0, backend)
    return importlib.import_module("microsoft_evidence.collector_command")


def fingerprint(config_path, association_path=None):
    digest = hashlib.sha256()
    for path in (config_path, association_path):
        if path is None:
            digest.update(b"absent\0")
        else:
            if not isinstance(path, Path) or not path.is_absolute():
                raise ValueError("Microsoft configuration paths must be absolute")
            payload = _read(path, 65536)
            digest.update(len(payload).to_bytes(8, "big"))
            digest.update(payload)
    return digest.hexdigest()


def configurations(recipe):
    if (
        fingerprint(recipe.network_config, recipe.association_config)
        != recipe.network_fingerprint
    ):
        raise ValueError("Microsoft configuration changed after scheduling")
    command = collector()
    config = command.load_configuration(recipe.network_config)
    associated = (
        None
        if recipe.association_config is None
        else command.load_configuration(recipe.association_config)
    )
    if config.scope != recipe.scope or config.bundle_root != recipe.bundle_root:
        raise ValueError(
            "Microsoft collector configuration differs from scheduled scope"
        )
    if associated is not None and (
        associated.scope != recipe.scope or associated.bundle_root != recipe.bundle_root
    ):
        raise ValueError(
            "Microsoft association configuration differs from scheduled scope"
        )
    if (
        fingerprint(recipe.network_config, recipe.association_config)
        != recipe.network_fingerprint
    ):
        raise ValueError("Microsoft configuration changed while loading")
    return config, associated


def collect(recipe, job, device, predecessor, since):
    config, associated = configurations(recipe)
    return collector().run(
        config,
        job.run_id,
        allow_network=True,
        device_snapshot=device,
        association_config=associated,
        predecessor=predecessor,
        since=since,
    )
