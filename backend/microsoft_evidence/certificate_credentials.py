"""Local certificate assertions for a prepared Microsoft application connection.

Private PEM keys remain outside repository artifacts. This resolver does not
create credentials, upload certificates, or contact Microsoft.
"""

import base64
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import stat
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt

from .cloud import cloud_profile
from .live_authority import MicrosoftCredentialMaterial, MicrosoftLiveAuthorityError


def _read_file(path, *, private):
    path = Path(path).absolute()
    if path.resolve() != path:
        raise ValueError("Credential paths cannot traverse symlinks")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        forbidden = 0o077 if private else 0o022
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_mode & forbidden
            or info.st_size > 65536
        ):
            raise ValueError("Unsafe credential file")
        value = stream.read(65537)
    if len(value) > 65536:
        raise ValueError("Oversized credential file")
    return value


class LocalCertificateResolver:
    def __init__(
        self,
        *,
        prepared,
        key_path,
        certificate_path,
        now=lambda: datetime.now(timezone.utc),
    ):
        self._prepared = prepared
        self._key_path = key_path
        self._certificate_path = certificate_path
        self._now = now

    def __repr__(self):
        return "<LocalCertificateResolver material=<redacted>>"

    def resolve(self, credential_reference_id):
        prepared = self._prepared
        if credential_reference_id != prepared.credential_reference_id:
            raise MicrosoftLiveAuthorityError(
                "Certificate reference does not match prepared authority"
            )
        try:
            now = self._now()
            if now.utcoffset() is None or now.utcoffset().total_seconds() != 0:
                raise ValueError("UTC required")
            key = serialization.load_pem_private_key(
                _read_file(self._key_path, private=True), password=None
            )
            certificate = x509.load_pem_x509_certificate(
                _read_file(self._certificate_path, private=False)
            )
            if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
                raise ValueError("RSA key of at least 2048 bits required")
            if key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ) != certificate.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ):
                raise ValueError("Certificate does not match key")
            if (
                not certificate.not_valid_before_utc
                <= now
                < certificate.not_valid_after_utc
            ):
                raise ValueError("Certificate is not current")
            expiry = min(now + timedelta(minutes=5), certificate.not_valid_after_utc)
            if int(expiry.timestamp()) <= int(now.timestamp()):
                raise ValueError("Certificate expires too soon")
            profile = cloud_profile(prepared.scope.cloud)
            audience = f"https://{profile.authority_host}/{prepared.scope.tenant_id}/oauth2/v2.0/token"
            thumbprint = (
                base64.urlsafe_b64encode(certificate.fingerprint(hashes.SHA256()))
                .rstrip(b"=")
                .decode()
            )
            assertion = jwt.encode(
                {
                    "aud": audience,
                    "iss": str(prepared.application_id),
                    "sub": str(prepared.application_id),
                    "jti": str(uuid4()),
                    "iat": int(now.timestamp()),
                    "nbf": int(now.timestamp()),
                    "exp": int(expiry.timestamp()),
                },
                key,
                algorithm="PS256",
                headers={"x5t#S256": thumbprint},
            )
        except (OSError, ValueError, TypeError, jwt.PyJWTError):
            raise MicrosoftLiveAuthorityError(
                "Local certificate credential could not be used; check file permissions, matching RSA key and certificate validity"
            ) from None
        return MicrosoftCredentialMaterial(kind="client_assertion", value=assertion)
