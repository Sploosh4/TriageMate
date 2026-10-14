"""Read configured public certificate metadata and journal expiry warnings only."""

from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import time
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from standalone.evidence_pipeline.contracts import identifier, utc
from standalone.evidence_pipeline.runtime import connect
from standalone.evidence_pipeline.collection.snapshot_bundle import _read
from .dispatch import identity
from .store import service_key


@dataclass(frozen=True)
class Certificate:
    reference_id: str
    label: str
    path: Path
    origin: str
    provenance: str
    warn_before_seconds: int = 30 * 86400

    def __post_init__(self):
        object.__setattr__(self, "reference_id", identifier(self.reference_id))
        identity(self.label)
        if (
            self.origin not in ("synthetic", "public", "lab")
            or not isinstance(self.provenance, str)
            or not self.provenance.strip()
            or not 1 <= len(self.provenance) <= 4096
        ):
            raise ValueError(
                "Certificate monitoring requires synthetic/public/authorised-lab provenance"
            )
        if not isinstance(self.path, Path) or not self.path.is_absolute():
            raise ValueError("Certificate monitoring requires an absolute path")
        if (
            type(self.warn_before_seconds) is not int
            or not 1 <= self.warn_before_seconds <= 366 * 86400
        ):
            raise ValueError(
                "Certificate warning window must be between one second and one year"
            )


def inspect(certificate, now):
    from .credential_metadata import CredentialMetadata, inspect_metadata

    now = utc(now)
    if isinstance(certificate, CredentialMetadata):
        return inspect_metadata(certificate, now)
    observed = dict(
        condition="unavailable", fingerprint=None, not_before=None, expires_at=None
    )
    try:
        # Only a certificate PEM is accepted; do not load keys or create assertions.
        if certificate.path.resolve() != certificate.path:
            raise ValueError("Certificate monitoring cannot traverse symlinks")
        raw = _read(certificate.path, 65536).strip()
        if (
            not raw.startswith(b"-----BEGIN CERTIFICATE-----")
            or not raw.endswith(b"-----END CERTIFICATE-----")
            or raw.count(b"-----BEGIN ") != 1
        ):
            raise ValueError("A single public certificate is required")
        parsed = x509.load_pem_x509_certificate(raw)
        before, after = parsed.not_valid_before_utc, parsed.not_valid_after_utc
        condition = (
            "not_yet_valid"
            if now < before
            else "expired"
            if now >= after
            else "expiring"
            if (after - now).total_seconds() <= certificate.warn_before_seconds
            else "healthy"
        )
        observed.update(
            condition=condition,
            fingerprint=parsed.fingerprint(hashes.SHA256()).hex(),
            not_before=before.isoformat(),
            expires_at=after.isoformat(),
        )
    except (ValueError, OSError, OverflowError, RuntimeError):
        pass  # Missing/unsafe/invalid metadata is explicit unavailability, never health.
    return observed


def record(cursor, key, certificate, observed, now, revision):
    cursor.execute(
        """SELECT event FROM evidence_pipeline.operation_events
      WHERE service_key=%s AND event->>'input_id'=%s AND event->>'kind' LIKE 'credential_%%'
      ORDER BY id DESC LIMIT 1""",
        (key, certificate.reference_id),
    )
    row = cursor.fetchone()
    previous = row[0] if row else None
    healthy = observed["condition"] == "healthy"
    if healthy and (previous is None or previous["kind"] == "credential_resolved"):
        return False
    if (
        previous is not None
        and all(previous.get(field) == value for field, value in observed.items())
        and all(
            previous.get(field) == getattr(certificate, field)
            for field in ("label", "origin", "provenance", "warn_before_seconds")
        )
    ):
        return False
    active = previous is not None and previous["kind"] != "credential_resolved"
    event = dict(
        kind="credential_resolved"
        if healthy
        else "credential_updated"
        if active
        else "credential_opened",
        input_id=certificate.reference_id,
        episode_id=previous["episode_id"] if active else str(uuid4()),
        at=utc(now).isoformat(),
        label=certificate.label,
        origin=certificate.origin,
        provenance=certificate.provenance,
        warn_before_seconds=certificate.warn_before_seconds,
        **observed,
    )
    cursor.execute(
        """INSERT INTO evidence_pipeline.operation_events(service_key,checkpoint_revision,recorded_at,event)
      VALUES(%s,%s,%s,%s::jsonb)""",
        (key, revision, now, json.dumps(event)),
    )
    return True


class CertificateMonitor:
    def __init__(self, key, certificates, *, connector=connect, clock=time.monotonic):
        self.key = service_key(key)
        self.certificates = tuple(certificates)
        self.connector, self.clock = connector, clock
        self.checked = float("-inf")

    def check(self, now=None):
        if not self.certificates or self.clock() - self.checked < 60:
            return
        now = utc(now or datetime.now(timezone.utc))
        observations = [(item, inspect(item, now)) for item in self.certificates]
        with closing(self.connector()) as conn, conn, conn.cursor() as cur:
            # Serialize with checkpoint commits and competing certificate checks.
            cur.execute(
                "SELECT revision FROM evidence_pipeline.operation_checkpoints WHERE service_key=%s FOR UPDATE",
                (self.key,),
            )
            row = cur.fetchone()
            if row is None:
                raise ValueError(
                    "Credential monitoring requires an existing operational service"
                )
            for certificate, observed in observations:
                record(cur, self.key, certificate, observed, now, row[0])
        self.checked = self.clock()
