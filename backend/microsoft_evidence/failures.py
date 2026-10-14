"""Closed failure labels for notifications; never infer credential expiry."""

from .live_authority import (
    MicrosoftTokenRequestError,
    MicrosoftTokenTimeout,
    MicrosoftTokenTransportFailure,
)
from .transport import (
    MicrosoftHTTPError,
    MicrosoftRequestTimeout,
    MicrosoftRequestTransportFailure,
)


def failure_code(error):
    if isinstance(error, MicrosoftTokenTimeout):
        return "microsoft_token_request_timeout"
    if isinstance(error, MicrosoftTokenTransportFailure):
        return "microsoft_token_transport_failed"
    if isinstance(error, MicrosoftRequestTimeout):
        return "microsoft_request_timeout"
    if isinstance(error, MicrosoftRequestTransportFailure):
        return "microsoft_request_transport_failed"
    if isinstance(error, (MicrosoftTokenRequestError, MicrosoftHTTPError)):
        if error.status == 429:
            return "microsoft_request_throttled"
        if isinstance(error.status, int) and 500 <= error.status <= 599:
            return "microsoft_service_unavailable"
    if isinstance(error, MicrosoftTokenRequestError) and error.status in (
        400,
        401,
        403,
    ):
        return "microsoft_token_request_rejected"
    if isinstance(error, MicrosoftHTTPError):
        if error.status == 401:
            return "microsoft_authentication_rejected"
        if error.status == 403:
            return "microsoft_access_forbidden"
    return "microsoft_collection_failed"
