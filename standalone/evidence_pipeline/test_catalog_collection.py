"""Synthetic search-to-detail collection and immutable offline continuation."""

from uuid import uuid4
import pytest
from standalone.evidence_pipeline.collection.catalog_collection import collect
from .test_catalog_discovery import payload as search, row, ID, OTHER
from .test_update_catalog import payload as detail


def test_discovered_details_resume_and_replay_without_network(tmp_path, monkeypatch):
    options = dict(
        kb="KB9999991", origin="synthetic", execution_id=str(uuid4()), limit=1
    )
    root = tmp_path / "bundle"
    fixtures = {ID: detail()}
    # Keep the second detail identity correct and its replacement distinct.
    fixtures[OTHER] = (
        detail()
        .replace(
            b"22222222-2222-4222-8222-222222222222",
            b"33333333-3333-4333-8333-333333333333",
        )
        .replace(ID.encode(), OTHER.encode())
    )
    first = collect(
        root,
        **options,
        synthetic_index=search(row() + row(OTHER, index=1), "1 - 2 of 2 (page 1 of 1)"),
        synthetic_payloads=fixtures,
    )
    assert first["search_complete"] and first["remaining"] == 1
    second = collect(
        root, **options, after=first["next_after"], synthetic_payloads=fixtures
    )
    assert second["remaining"] == 0 and second["outcomes"][0]["outcome"] == "success"

    def denied(*args, **kwargs):
        raise AssertionError("Replay used network")

    monkeypatch.setattr("http.client.HTTPSConnection", denied)
    assert collect(root, **options, replay_only=True) == first
    assert (
        collect(root, **options, replay_only=True, after=first["next_after"]) == second
    )


@pytest.mark.parametrize(
    "damage", ["payload", "identity", "origin", "execution", "symlink"]
)
def test_discovery_replay_rejects_changed_authority_or_evidence(tmp_path, damage):
    root = tmp_path / "bundle"
    options = dict(kb="KB9999991", origin="synthetic", execution_id=str(uuid4()))
    collect(
        root, **options, synthetic_index=search(), synthetic_payloads={ID: detail()}
    )
    if damage == "payload":
        (root / "search.html").write_bytes(b"changed")
    elif damage == "identity":
        options["kb"] = "KB9999992"
    elif damage == "origin":
        options["origin"] = "public"
    elif damage == "execution":
        options["execution_id"] = str(uuid4())
    else:
        saved = root / "search.html"
        saved.rename(root / "saved.html")
        saved.symlink_to(root / "saved.html")
    with pytest.raises(ValueError):
        collect(root, **options, replay_only=True)


def test_search_coverage_and_unprepared_details_are_explicit(tmp_path):
    result = collect(
        tmp_path / "bundle",
        kb="KB9999991",
        origin="synthetic",
        execution_id=str(uuid4()),
        synthetic_index=search(count="1 - 1 of 2 (page 1 of 2)"),
    )
    assert not result["search_complete"] and result["undiscovered_results"] == 1
    assert result["outcomes"] == [
        dict(path=ID, outcome="pending", database_imported=False)
    ]


def test_public_requires_opt_in_and_rejects_relabelled_synthetic_evidence(tmp_path):
    args = dict(kb="KB9999991", origin="public", execution_id=str(uuid4()))
    with pytest.raises(ValueError):
        collect(tmp_path / "bundle", **args)
    with pytest.raises(ValueError):
        collect(
            tmp_path / "bundle", **args, allow_network=True, synthetic_index=search()
        )


def test_interrupted_search_is_retained_and_not_silently_retried(tmp_path, monkeypatch):
    calls = []

    def failed(url):
        calls.append(url)
        raise ValueError("Synthetic transport failure")

    monkeypatch.setattr(
        "standalone.evidence_pipeline.collection.catalog_collection._download_url",
        failed,
    )
    options = dict(
        kb="KB9999991", origin="public", execution_id=str(uuid4()), allow_network=True
    )
    with pytest.raises(ValueError):
        collect(tmp_path / "run", **options)
    with pytest.raises(FileNotFoundError):
        collect(tmp_path / "run", **options)
    assert len(calls) == 1


@pytest.mark.parametrize("include_detail,expected", [(True, 0), (False, 1)])
def test_command_reports_pending_details_without_claiming_success(
    tmp_path, capsys, include_detail, expected
):
    import json
    from standalone.evidence_pipeline.collection.catalog_collection import main

    index = tmp_path / "index.html"
    index.write_bytes(search())
    item = tmp_path / "detail.html"
    item.write_bytes(detail())
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({ID: item.name} if include_detail else {}))
    status = main(
        [
            "--kb",
            "KB9999991",
            "--origin",
            "synthetic",
            "--execution-id",
            str(uuid4()),
            "--output",
            str(tmp_path / "bundle"),
            "--synthetic-index",
            str(index),
            "--synthetic-manifest",
            str(manifest),
        ]
    )
    assert status == expected
    result = json.loads(capsys.readouterr().out)
    assert result["outcomes"][0]["outcome"] == (
        "success" if include_detail else "pending"
    )
