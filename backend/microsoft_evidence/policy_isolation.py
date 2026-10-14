"""Recheck a pinned lab policy/group before any report export is requested."""

import json
import time

import httpx

from standalone.evidence_pipeline.parsing.devices import normalize_devices
from .transport import (
    MicrosoftHTTPError,
    MicrosoftTransportError,
    read_response_content,
    verify_microsoft_transport_authority,
)
from .update_report_pipeline import isolation_group_id, policy_id


def verify_policy_isolation(*, client, prepared, token, scope, device_snapshot, now):
    policy = policy_id(scope)
    group = isolation_group_id(scope)
    devices = normalize_devices(device_snapshot)
    if len(devices) != 1 or devices[0].registration_id is None:
        raise ValueError("Policy isolation requires one explicitly registered device")
    if not {"GroupMember.Read.All", "Device.Read.All"} <= set(prepared.expected_roles):
        raise ValueError(
            "Policy isolation requires approved membership and device reads"
        )
    expected_registration = devices[0].registration_id
    base = "https://" + prepared.endpoint.host

    def get(path, params=None):
        verify_microsoft_transport_authority(prepared=prepared, token=token, now=now())
        deadline = time.monotonic() + 20
        try:
            with client.stream(
                "GET",
                base + path,
                params=params,
                headers={
                    "Authorization": token.authorization_header(),
                    "Accept": "application/json",
                },
                timeout=20,
                follow_redirects=False,
            ) as response:
                if response.status_code != 200:
                    raise MicrosoftHTTPError(response.status_code)
                payload = read_response_content(
                    response, deadline=deadline, cancelled=lambda: False
                )
        except httpx.HTTPError as exc:
            raise MicrosoftTransportError("Policy isolation request failed") from exc
        body = json.loads(payload)
        if not isinstance(body, dict) or body.get("@odata.nextLink"):
            raise ValueError("Policy isolation requires complete unpaginated evidence")
        values = body.get("value")
        if (
            not isinstance(values, list)
            or len(values) != 1
            or not isinstance(values[0], dict)
        ):
            raise ValueError(
                "Policy isolation requires exactly one assignment and one member"
            )
        return values[0]

    assignment = get(
        "/beta/deviceManagement/windowsQualityUpdateProfiles/" + policy + "/assignments"
    )
    target = assignment.get("target")
    if (
        not isinstance(target, dict)
        or target.get("@odata.type") != "#microsoft.graph.groupAssignmentTarget"
        or target.get("groupId") != group
        or target.get("deviceAndAppManagementAssignmentFilterId")
        or target.get("deviceAndAppManagementAssignmentFilterType")
        not in (None, "none")
    ):
        raise ValueError("Policy assignment differs from its pinned unfiltered group")
    member = get(
        "/v1.0/groups/" + group + "/members", {"$select": "id,deviceId", "$top": "2"}
    )
    if (
        member.get("@odata.type") != "#microsoft.graph.device"
        or member.get("deviceId") != expected_registration
    ):
        raise ValueError(
            "Policy group does not contain only the designated registered device"
        )
