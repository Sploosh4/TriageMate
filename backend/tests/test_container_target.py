"""Only the explicit container deployment can select Compose's database service."""

import json

import pytest

from backend.database.target import load_target


@pytest.mark.parametrize(
    "deployment,host,allowed",
    [
        ("container", "db", True),
        ("", "db", False),
        ("container", "example.com", False),
        ("container", "db,example.com", False),
        ("container", "127.0.0.1", True),
    ],
)
def test_compose_host_is_explicit_and_other_network_hosts_stay_rejected(
    tmp_path, monkeypatch, deployment, host, allowed
):
    tmp_path.chmod(0o700)
    configuration = tmp_path / "target.json"
    configuration.write_text(
        json.dumps(
            {
                "host": host,
                "port": 5432,
                "database": "triagemate",
                "work": str(tmp_path),
            }
        )
    )
    configuration.chmod(0o600)
    monkeypatch.setenv("TRIAGEMATE_DATABASE_TARGET", str(configuration))
    monkeypatch.setenv("TRIAGEMATE_DEPLOYMENT", deployment)
    if allowed:
        assert load_target().host == host
    else:
        with pytest.raises(ValueError):
            load_target()
