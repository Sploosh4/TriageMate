"""Generated RSA keys only; no installed lab credential is opened."""

from datetime import timedelta
import base64

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import jwt
import pytest

from microsoft_evidence.certificate_credentials import LocalCertificateResolver
from microsoft_evidence.live_authority import MicrosoftLiveAuthorityError
from tests.test_microsoft_live_authority import NOW, _live_prepared


@pytest.fixture
def credential(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "TriageMate synthetic test")]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    private = tmp_path / "key.pem"
    public = tmp_path / "certificate.pem"
    private.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    private.chmod(0o600)
    public.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    public.chmod(0o644)
    prepared = _live_prepared()
    resolver = LocalCertificateResolver(
        prepared=prepared, key_path=private, certificate_path=public, now=lambda: NOW
    )
    return resolver, prepared, key, cert, private, public


def test_assertion_signature_audience_thumbprint_and_short_unique_lifetime(credential):
    resolver, prepared, key, cert, _, _ = credential
    first = resolver.resolve(prepared.credential_reference_id)
    token = first.reveal_for_token_request()
    claims = jwt.decode(
        token,
        key.public_key(),
        algorithms=["PS256"],
        audience=f"https://login.microsoftonline.com/{prepared.scope.tenant_id}/oauth2/v2.0/token",
        options={"verify_exp": False, "verify_nbf": False, "verify_iat": False},
    )
    assert claims["iss"] == claims["sub"] == str(prepared.application_id)
    assert claims["exp"] - claims["iat"] == 300
    assert claims["nbf"] == claims["iat"]
    assert (
        jwt.get_unverified_header(token)["x5t#S256"]
        == base64.urlsafe_b64encode(cert.fingerprint(hashes.SHA256()))
        .rstrip(b"=")
        .decode()
    )
    assert (
        token
        != resolver.resolve(prepared.credential_reference_id).reveal_for_token_request()
    )
    assert token not in repr(first) and "key.pem" not in repr(resolver)


@pytest.mark.parametrize(
    "problem", ("permissions", "symlink", "mismatch", "expired", "reference")
)
def test_unsafe_or_wrong_certificate_rejected(credential, problem):
    resolver, prepared, _, _, private, public = credential
    reference = prepared.credential_reference_id
    if problem == "permissions":
        private.chmod(0o644)
    elif problem == "symlink":
        original = private.with_suffix(".original")
        private.rename(original)
        private.symlink_to(original)
    elif problem == "mismatch":
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private.write_bytes(
            other.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    elif problem == "expired":
        resolver = LocalCertificateResolver(
            prepared=prepared,
            key_path=private,
            certificate_path=public,
            now=lambda: NOW + timedelta(days=2),
        )
    else:
        reference = "other-reference"
    with pytest.raises(MicrosoftLiveAuthorityError):
        resolver.resolve(reference)


def test_certificate_assertion_is_used_for_opaque_token_exchange(credential):
    from urllib.parse import parse_qs
    import httpx
    from microsoft_evidence.resource_authority import acquire_resource_token

    resolver, prepared, key, _, _, _ = credential

    def handler(request):
        form = parse_qs(request.content.decode())
        assert "client_secret" not in form
        assert form["client_assertion_type"] == [
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        ]
        claims = jwt.decode(
            form["client_assertion"][0],
            key.public_key(),
            algorithms=["PS256"],
            audience=str(request.url),
            options={"verify_exp": False, "verify_nbf": False, "verify_iat": False},
        )
        assert claims["sub"] == str(prepared.application_id)
        assert b"PRIVATE KEY" not in request.content
        return httpx.Response(
            200,
            json={
                "access_token": "synthetic-opaque-response",
                "token_type": "Bearer",
                "expires_in": 3600,
            },
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        token = acquire_resource_token(
            prepared=prepared, credential_resolver=resolver, client=client, now=NOW
        )
    assert token.authorization_header() == "Bearer synthetic-opaque-response"
