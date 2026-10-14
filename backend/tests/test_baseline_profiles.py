"""Profile selection requires exact independent authority/layout contracts."""

import pytest

from backend.database.baseline.profiles import (
    PROFILES,
    identify,
    identify_layout,
    read_contract,
)


@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize("predecessor", (False, True))
def test_profile_requires_exact_schema_and_authority(profile, predecessor):
    expected = read_contract(profile, predecessor=predecessor)
    assert identify(expected, predecessor=predecessor) == profile
    assert identify_layout(expected) == (profile, predecessor)
    for category in ("roles", "object_acl", "database_acl", "policies"):
        altered = {**expected, category: "0" * 64}
        with pytest.raises(ValueError, match="exactly one"):
            identify_layout(altered)
    with pytest.raises(ValueError, match="exactly one"):
        identify_layout({**expected, "unexpected": "0" * 64})


def test_unknown_profile_is_refused():
    with pytest.raises(ValueError, match="Unknown database installation profile"):
        read_contract("derived-from-hostname")
