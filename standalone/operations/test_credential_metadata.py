"""Synthetic expiry declarations never contain credential material."""

from dataclasses import asdict, replace
from datetime import timedelta
import json
from uuid import uuid4

import pytest

from .certificates import CertificateMonitor, inspect
from .credential_metadata import CredentialMetadata
from .configuration import load as configure
from .dispatch import Dispatcher
from .notifications import load
from .supervisor import PostgresRepository
from .test_certificates import clean
from .test_configuration import save
from .test_dispatch import NOW


def declaration(tmp_path, *, days=5, reference=None):
    reference = reference or str(uuid4())
    path = tmp_path / "metadata.json"
    path.write_text(
        json.dumps(
            dict(
                version=1,
                reference_id=reference,
                credential_type="client_secret",
                not_before=None,
                expires_at=(NOW + timedelta(days=days)).isoformat(),
            )
        )
    )
    path.chmod(0o600)
    return CredentialMetadata(
        reference,
        "Synthetic expiry declaration",
        path,
        "synthetic",
        "Generated TriageMate metadata; contains no credential",
    )


@pytest.mark.parametrize(
    "days,condition", [(5, "expiring"), (-1, "expired"), (40, "healthy")]
)
@pytest.mark.parametrize("origin", ["synthetic", "public", "lab"])
def test_declared_expiry_does_not_require_or_read_a_secret(
    tmp_path, days, condition, origin
):
    value = replace(declaration(tmp_path, days=days), origin=origin)
    observed = inspect(value, NOW)
    assert observed["condition"] == condition
    assert observed["not_before"] is None
    assert observed["metadata_type"] == "client_secret"


@pytest.mark.parametrize(
    "damage",
    [
        "secret",
        "duplicate",
        "wrong_reference",
        "missing_expiry",
        "permissions",
        "symlink",
        "unknown_type",
    ],
)
def test_invalid_or_unknown_metadata_never_claims_healthy(tmp_path, damage):
    value = declaration(tmp_path)
    data = json.loads(value.path.read_text())
    if damage == "secret":
        data["secret"] = "synthetic-forbidden-field"
    elif damage == "wrong_reference":
        data["reference_id"] = str(uuid4())
    elif damage == "missing_expiry":
        data["expires_at"] = None
    elif damage == "unknown_type":
        data["credential_type"] = "arbitrary"
    value.path.write_text(json.dumps(data))
    if damage == "permissions":
        value.path.chmod(0o644)
    elif damage == "duplicate":
        value.path.write_text(value.path.read_text()[:-1] + ',"version":1}')
    elif damage == "symlink":
        target = tmp_path / "saved.json"
        value.path.rename(target)
        value.path.symlink_to(target)
    observed = inspect(value, NOW)
    assert observed["condition"] == "unavailable"
    assert observed["fingerprint"] is None


def test_configuration_journal_notification_and_recovery(tmp_path):
    value = declaration(tmp_path)
    item = {**asdict(value), "path": str(value.path)}
    config = save(
        tmp_path,
        dict(
            version=1,
            concurrency=1,
            grace_seconds=0,
            inputs=[],
            credential_metadata=[item],
        ),
    )
    assert configure(config, now=NOW).certificates == (value,)
    key = "synthetic-expiry-" + str(uuid4())
    ticks = [0]
    monitor = CertificateMonitor(key, [value], clock=lambda: ticks[0])
    try:
        PostgresRepository(key).commit(0, Dispatcher([], now=NOW))
        monitor.check(NOW)
        [warning] = load(key)
        assert warning["synthetic"] and warning["status"] == "unresolved"
        assert "declared credential expiry" in warning["message"]
        assert (
            "Revocation and provider acceptance remain unknown"
            in warning["details"]["interpretation"]
        )
        assert str(value.path) not in str(warning)
        declaration(tmp_path, days=40, reference=value.reference_id)
        ticks[0] = 60
        monitor.check(NOW)
        [resolved] = load(key)
        assert resolved["id"] == warning["id"] and resolved["status"] == "resolved"
    finally:
        clean(key)


@pytest.mark.parametrize("damage", ["overflow", "metadata_loop", "certificate_loop"])
def test_invalid_metadata_does_not_abort_other_monitor_observations(
    tmp_path, monkeypatch, damage
):
    from unittest.mock import MagicMock
    from . import certificates
    from .test_certificates import certificate

    bad = declaration(tmp_path)
    if damage == "overflow":
        data = json.loads(bad.path.read_text())
        data["expires_at"] = "0001-01-01T00:00:00+14:00"
        bad.path.write_text(json.dumps(data))
    else:
        loop = tmp_path / "loop"
        loop.symlink_to(loop)
        bad = replace(bad, path=loop)
        if damage == "certificate_loop":
            bad = replace(certificate(tmp_path / "bad.pem"), path=loop)
    good = certificate(tmp_path / "good.pem")
    conn = MagicMock()
    conn.__enter__.return_value = conn
    cursor = conn.cursor.return_value.__enter__.return_value
    cursor.fetchone.return_value = (1,)
    observations = []
    monkeypatch.setattr(
        certificates,
        "record",
        lambda cur, key, item, observed, now, revision: observations.append(
            (item.reference_id, observed)
        ),
    )
    monitor = CertificateMonitor(
        "synthetic-metadata-boundary",
        [bad, good],
        connector=lambda: conn,
        clock=lambda: 100,
    )
    monitor.check(NOW)
    assert [row[1]["condition"] for row in observations] == ["unavailable", "expiring"]
    assert observations[0][1]["fingerprint"] is None
    assert monitor.checked == 100
    conn.close.assert_called_once()
