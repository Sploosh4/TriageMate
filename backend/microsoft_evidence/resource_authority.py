"""Acquire opaque Microsoft resource tokens without inspecting provider claims.

Microsoft-owned API access tokens are for the resource server to validate.
Local authority derives from the exact server-owned client-credentials request
and HTTPS token response, not invented JWT claims or application user identity.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
import json

import httpx

from .cloud import PreparedCollectionContext, cloud_profile
from .live_authority import MicrosoftTokenRequestError
from .live_authority import MicrosoftLiveAuthorityError
from .live_authority import MicrosoftTokenTimeout, MicrosoftTokenTransportFailure


def binding(prepared):
    return hashlib.sha256(prepared.model_dump_json().encode()).hexdigest()


@dataclass(frozen=True)
class AcquisitionEvidence:
    prepared_sha256: str
    acquired_at: datetime
    expires_at: datetime


class MicrosoftResourceToken:
    __slots__ = ("_token", "acquisition")

    def __init__(self, token, acquisition):
        self._token = token
        self.acquisition = acquisition

    def authorization_header(self):
        return "Bearer " + self._token

    def __repr__(self):
        return "<MicrosoftResourceToken token=<redacted>>"

    __str__ = __repr__


def verify_resource_authority(prepared, token, now):
    evidence = token.acquisition
    if (
        prepared.classification != "live"
        or evidence.prepared_sha256 != binding(prepared)
        or not evidence.acquired_at <= now < evidence.expires_at
    ):
        raise MicrosoftLiveAuthorityError(
            "Acquired Microsoft token does not match current collection authority"
        )


def acquire_resource_token(
    *,
    prepared: PreparedCollectionContext,
    credential_resolver,
    client: httpx.Client,
    now: datetime,
) -> MicrosoftResourceToken:
    if now.utcoffset() is None or now.utcoffset().total_seconds() != 0:
        raise ValueError("Token acquisition requires UTC")
    if prepared.classification != "live":
        raise MicrosoftLiveAuthorityError(
            "Token acquisition requires live server-owned policy"
        )
    profile = cloud_profile(prepared.scope.cloud)
    url = (
        f"https://{profile.authority_host}/{prepared.scope.tenant_id}/oauth2/v2.0/token"
    )
    material = credential_resolver.resolve(prepared.credential_reference_id)
    form = {
        "client_id": str(prepared.application_id),
        "grant_type": "client_credentials",
        "scope": prepared.audience + "/.default",
    }
    if material.kind == "client_secret":
        form["client_secret"] = material.reveal_for_token_request()
    elif material.kind == "client_assertion":
        form.update(
            client_assertion=material.reveal_for_token_request(),
            client_assertion_type="urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        )
    else:
        raise MicrosoftLiveAuthorityError("Unsupported credential material")
    try:
        with client.stream(
            "POST", url, data=form, timeout=15.0, follow_redirects=False
        ) as response:
            if response.status_code != 200:
                raise MicrosoftTokenRequestError(response.status_code)
            if (
                response.headers.get("content-type", "").split(";", 1)[0].lower()
                != "application/json"
            ):
                raise MicrosoftLiveAuthorityError(
                    "Invalid Microsoft token response type"
                )
            body = bytearray()
            for chunk in response.iter_bytes():
                body.extend(chunk)
    except httpx.TimeoutException:
        raise MicrosoftTokenTimeout("Microsoft token request timed out") from None
    except httpx.TransportError:
        raise MicrosoftTokenTransportFailure(
            "Microsoft token transport failed"
        ) from None
    except httpx.HTTPError:
        raise MicrosoftLiveAuthorityError(
            "Microsoft token acquisition failed"
        ) from None

    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate field")
            value[key] = item
        return value

    try:
        payload = json.loads(body, object_pairs_hook=unique)
        value, kind, expires = (
            payload["access_token"],
            payload["token_type"],
            payload["expires_in"],
        )
        if (
            not isinstance(value, str)
            or not 1 <= len(value) <= 65536
            or any(ord(char) < 33 or ord(char) > 126 for char in value)
            or not isinstance(kind, str)
            or kind.lower() != "bearer"
            or type(expires) is not int
            or not 1 <= expires <= 86400
        ):
            raise ValueError("Invalid fields")
    except (ValueError, TypeError, KeyError, RecursionError):
        raise MicrosoftLiveAuthorityError(
            "Invalid Microsoft token response fields"
        ) from None
    return MicrosoftResourceToken(
        value,
        AcquisitionEvidence(binding(prepared), now, now + timedelta(seconds=expires)),
    )
