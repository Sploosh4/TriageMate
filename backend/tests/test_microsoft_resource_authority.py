"""Opaque tokens use the exact client-credentials exchange, never JWT decoding."""

from dataclasses import replace
from datetime import timedelta
from uuid import uuid4
import httpx
import pytest

from microsoft_evidence.live_authority import (
    MicrosoftCredentialMaterial,
    MicrosoftLiveAuthorityError,
)
from microsoft_evidence.resource_authority import (
    acquire_resource_token,
    verify_resource_authority,
)
from microsoft_evidence.pipeline import connection_scope, collect_devices
from microsoft_evidence.transport import MicrosoftHttpTransport
from tests.test_microsoft_live_authority import NOW, _live_prepared
from tests.test_microsoft_pipeline import scope


class Resolver:
    def resolve(self, reference):
        assert reference == "local-test-credential-reference"
        return MicrosoftCredentialMaterial(
            kind="client_secret", value="synthetic-credential"
        )


def test_opaque_token_collects_without_jwt_claims():
    source = scope()
    prepared = _live_prepared(scope=connection_scope(source))
    calls = []

    def handler(request):
        calls.append(request)
        if request.method == "POST":
            assert (
                str(request.url)
                == f"https://login.microsoftonline.com/{source.tenant_id}/oauth2/v2.0/token"
            )
            assert b"client_credentials" in request.content
            return httpx.Response(
                200,
                json={
                    "access_token": "opaque-synthetic-token",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                },
            )
        assert request.headers["authorization"] == "Bearer opaque-synthetic-token"
        return httpx.Response(200, json={"value": []})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        token = acquire_resource_token(
            prepared=prepared, credential_resolver=Resolver(), client=client, now=NOW
        )
        assert "opaque-synthetic-token" not in repr(token)
        result = collect_devices(
            scope=source,
            execution_id=str(uuid4()),
            prepared=prepared,
            token=token,
            transport=MicrosoftHttpTransport(client=client, now=lambda: NOW),
            now=lambda: NOW,
        )
    assert result.complete and result.records() == []
    assert len(calls) == 2
    other = prepared.model_copy(
        update={"scope": connection_scope(replace(source, connection_id=str(uuid4())))}
    )
    with pytest.raises(MicrosoftLiveAuthorityError):
        verify_resource_authority(other, token, NOW)
    with pytest.raises(MicrosoftLiveAuthorityError):
        verify_resource_authority(prepared, token, NOW + timedelta(hours=1))


@pytest.mark.parametrize(
    "patch",
    (
        {"expires_in": True},
        {"expires_in": 0},
        {"expires_in": 86401},
        {"access_token": "bad\r\nheader"},
        {"token_type": "Basic"},
        {"access_token": ""},
        {"access_token": "x" * 65537},
    ),
)
def test_invalid_response_never_authorizes(patch):
    payload = {
        "access_token": "opaque-synthetic",
        "token_type": "Bearer",
        "expires_in": 3600,
        **patch,
    }
    with httpx.Client(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=payload))
    ) as client:
        with pytest.raises(MicrosoftLiveAuthorityError):
            acquire_resource_token(
                prepared=_live_prepared(),
                credential_resolver=Resolver(),
                client=client,
                now=NOW,
            )


def test_redirect_never_receives_credentials_even_when_client_follows_redirects():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(
            302, headers={"Location": "https://elsewhere.example/token"}
        )

    with httpx.Client(
        follow_redirects=True, transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(MicrosoftLiveAuthorityError, match="302"):
            acquire_resource_token(
                prepared=_live_prepared(),
                credential_resolver=Resolver(),
                client=client,
                now=NOW,
            )
    assert len(calls) == 1


def test_transport_exception_does_not_expose_request_credentials():
    def handler(request):
        raise httpx.ConnectError("synthetic-sensitive-provider-detail", request=request)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(MicrosoftLiveAuthorityError) as error:
            acquire_resource_token(
                prepared=_live_prepared(),
                credential_resolver=Resolver(),
                client=client,
                now=NOW,
            )
    assert "synthetic-sensitive" not in str(error.value)
    assert error.value.__suppress_context__
