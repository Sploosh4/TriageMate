"""Index walking cannot mistake pending records or a pass budget for completion."""

from uuid import uuid4
import pytest
from standalone.evidence_pipeline.test_redhat_collection_run import INDEX, fixtures


def options():
    return dict(
        origin="synthetic",
        execution_id=str(uuid4()),
        synthetic_index=INDEX,
        synthetic_payloads=fixtures(),
        record_limit=1,
    )


@pytest.fixture
def imported(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "standalone.evidence_pipeline.collection.redhat_collection._download_url",
        lambda *a, **k: pytest.fail("Synthetic execution accessed the network"),
    )
    monkeypatch.setattr(
        "standalone.evidence_pipeline.collection.redhat_collection.register",
        lambda scope: None,
    )

    def ingest(snapshot):
        calls.append(snapshot)
        return {"replayed": False}

    monkeypatch.setattr(
        "standalone.evidence_pipeline.collection.redhat_collection.ingest_public",
        ingest,
    )
    return calls


@pytest.mark.parametrize(
    "damage",
    [None, "origin", "unknown_record", "duplicate_key", "permissions", "record_type"],
)
def test_synthetic_fixture_contract(tmp_path, damage):
    import json
    from .redhat_worker import fixtures as load_fixtures

    document = dict(
        origin="synthetic",
        index=INDEX.decode(),
        records={key: value.decode() for key, value in fixtures().items()},
    )
    if damage == "origin":
        document["origin"] = "public"
    elif damage == "unknown_record":
        document["records"]["2099/rhsa-2099_9999.json"] = "{}"
    elif damage == "record_type":
        document["records"][next(iter(document["records"]))] = {}
    wire = json.dumps(document)
    if damage == "duplicate_key":
        wire = wire.replace(
            '"origin": "synthetic"', '"origin": "synthetic", "origin": "synthetic"'
        )
    path = tmp_path / "fixture.json"
    path.write_text(wire)
    path.chmod(0o644 if damage == "permissions" else 0o600)
    if damage:
        with pytest.raises(ValueError):
            load_fixtures(path)
    else:
        assert load_fixtures(path) == (INDEX, fixtures())
