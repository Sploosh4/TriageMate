"""Certificate warnings use generated synthetic certificates, never live credentials."""

from contextlib import closing
from dataclasses import replace
from datetime import timedelta
import time
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID
import pytest

from standalone.evidence_pipeline.runtime import local_database
from .certificates import Certificate, CertificateMonitor, inspect
from .configuration import load as configure
from .dispatch import Dispatcher
from .notifications import load
from .supervisor import PostgresRepository
from .test_dispatch import NOW
from .test_configuration import save

pytestmark = pytest.mark.xdist_group("retained_evidence_schema")


def certificate(path, before=NOW - timedelta(days=1), after=NOW + timedelta(days=5)):
    key = ed25519.Ed25519PrivateKey.generate()
    name = x509.Name(
        [
            x509.NameAttribute(
                NameOID.COMMON_NAME, "Explicitly synthetic test certificate"
            )
        ]
    )
    value = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(before)
        .not_valid_after(after)
        .sign(key, None)
    )
    path.write_bytes(value.public_bytes(serialization.Encoding.PEM))
    path.chmod(0o600)
    return Certificate(
        str(uuid4()),
        "Synthetic certificate",
        path,
        "synthetic",
        "TriageMate-generated synthetic public certificate",
        10 * 86400,
    )


def test_validity_boundaries_preserve_absolute_dates(tmp_path):
    definition = certificate(tmp_path / "certificate.pem")
    assert inspect(definition, NOW)["condition"] == "expiring"
    expired = inspect(definition, NOW + timedelta(days=5))
    assert expired["condition"] == "expired"
    assert len(expired["fingerprint"]) == 64
    assert inspect(definition, NOW - timedelta(days=2))["condition"] == "not_yet_valid"
    assert (
        inspect(replace(definition, warn_before_seconds=1), NOW)["condition"]
        == "healthy"
    )


@pytest.mark.parametrize(
    "damage",
    [
        "missing",
        "permissions",
        "symlink",
        "invalid",
        "extra_pem",
        "private_key",
        "directory",
    ],
)
def test_unreadable_or_unsafe_certificate_never_becomes_healthy(tmp_path, damage):
    definition = certificate(tmp_path / "certificate.pem")
    if damage == "missing":
        definition.path.unlink()
    elif damage == "permissions":
        definition.path.chmod(0o644)
    elif damage == "symlink":
        link = tmp_path / "linked.pem"
        link.symlink_to(definition.path)
        definition = replace(definition, path=link)
    elif damage == "invalid":
        definition.path.write_text("synthetic invalid certificate")
    elif damage == "extra_pem":
        definition.path.write_bytes(definition.path.read_bytes() * 2)
    elif damage == "private_key":
        generated_key = ed25519.Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        definition.path.write_bytes(definition.path.read_bytes() + generated_key)
    else:
        definition = replace(definition, path=tmp_path)
    assert inspect(definition, NOW) == dict(
        condition="unavailable", fingerprint=None, not_before=None, expires_at=None
    )


def clean(key):
    with closing(local_database().connect()) as conn, conn, conn.cursor() as cur:
        cur.execute(
            "DELETE FROM evidence_pipeline.operation_events WHERE service_key=%s",
            (key,),
        )
        cur.execute(
            "DELETE FROM evidence_pipeline.operation_checkpoints WHERE service_key=%s",
            (key,),
        )


@pytest.mark.parametrize("origin", ["synthetic", "public", "lab"])
def test_journal_promotes_expiry_and_resolves_replacement_without_duplicate_on_restart(
    tmp_path,
    origin,
):
    # Generated certificates exercise origin routing; these are not lab observations.
    definition = replace(certificate(tmp_path / "certificate.pem"), origin=origin)
    key = "synthetic-certificates-" + str(uuid4())
    ticks = [0]
    monitor = CertificateMonitor(key, [definition], clock=lambda: ticks[0])
    try:
        PostgresRepository(key).commit(0, Dispatcher([], now=NOW))
        monitor.check(NOW)
        [warning] = load(key)
        assert warning["urgency"] == "moderate"
        assert warning["synthetic"] is (origin == "synthetic")
        assert str(definition.path) not in str(warning)
        ticks[0] = 60
        monitor.check(NOW + timedelta(days=5))
        [expired] = load(key)
        assert expired["id"] == warning["id"] and expired["urgency"] == "critical"
        certificate(definition.path, after=NOW + timedelta(days=40))
        ticks[0] = 120
        monitor.check(NOW + timedelta(days=5))
        [resolved] = load(key)
        assert resolved["id"] == warning["id"] and resolved["status"] == "resolved"
        CertificateMonitor(key, [definition]).check(NOW + timedelta(days=5))
        with closing(local_database().connect()) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT count(*) FROM evidence_pipeline.operation_events WHERE service_key=%s",
                (key,),
            )
            assert cur.fetchone() == (3,)
    finally:
        clean(key)


def test_explicit_lab_certificate_configuration_preserves_origin(tmp_path):
    from dataclasses import asdict

    definition = replace(certificate(tmp_path / "certificate.pem"), origin="lab")
    item = {**asdict(definition), "path": str(definition.path)}
    document = dict(
        version=1, concurrency=1, grace_seconds=0, inputs=[], certificates=[item]
    )
    assert configure(save(tmp_path, document), now=NOW).certificates == (definition,)


def test_configured_application_monitor_warns_only_when_running(tmp_path):
    from dataclasses import asdict
    from datetime import datetime, timezone

    from app.services.operations_api import create_service

    now = datetime.now(timezone.utc)
    definition = certificate(
        tmp_path / "certificate.pem", now - timedelta(days=1), now + timedelta(days=5)
    )
    item = {**asdict(definition), "path": str(definition.path)}
    config = save(
        tmp_path,
        dict(version=1, concurrency=1, grace_seconds=0, inputs=[], certificates=[item]),
    )
    assert configure(config, now=now).certificates == (definition,)
    key = "synthetic-configured-certificate-" + str(uuid4())
    service = None
    try:
        service = create_service(tmp_path, config, key)
        assert service.status()["state"] == "off"
        assert load(key) == []
        service.request_mode("running")
        deadline = time.monotonic() + 5
        notices = []
        while time.monotonic() < deadline:
            notices = load(key)
            if notices:
                break
            time.sleep(0.05)
        assert notices and notices[0]["category"] == "credential-expiry"
        assert service.close(timeout=5)
    finally:
        if service:
            service.close(timeout=5)
        clean(key)


@pytest.mark.parametrize(
    "damage", ["origin", "duplicate", "relative", "window", "extra"]
)
def test_configuration_rejects_invalid_certificate_monitor(tmp_path, damage):
    from dataclasses import asdict

    item = asdict(certificate(tmp_path / "certificate.pem"))
    item["path"] = str(item["path"])
    document = dict(
        version=1, concurrency=1, grace_seconds=0, inputs=[], certificates=[item]
    )
    if damage == "origin":
        item["origin"] = "private"
    elif damage == "duplicate":
        document["certificates"].append(item)
    elif damage == "relative":
        item["path"] = "relative.pem"
    elif damage == "window":
        item["warn_before_seconds"] = True
    else:
        item["private_key_path"] = "must-not-be-loaded"
    with pytest.raises(ValueError):
        configure(save(tmp_path, document), now=NOW)
