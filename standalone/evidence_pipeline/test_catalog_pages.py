"""Synthetic multi-page provenance, replay, coverage and failure checks."""

import hashlib
import json
from uuid import uuid4

import pytest

from standalone.evidence_pipeline.collection.catalog_collection import collect
from standalone.evidence_pipeline.parsing.catalog_discovery import search_url
from standalone.evidence_pipeline.collection.catalog_pages import saved_pages
from .test_catalog_discovery import payload, row, ID, OTHER
from ..operations.catalog_proof import CatalogProof


def setup(tmp_path):
    run = str(uuid4())
    root = tmp_path / run
    first = payload(count="1 - 1 of 2 (page 1 of 2)")
    second = payload(row(OTHER), count="2 - 2 of 2 (page 2 of 2)")
    options = dict(
        kb="KB9999991",
        origin="synthetic",
        execution_id=run,
        synthetic_index=first,
        synthetic_pages={2: second},
    )
    return root, first, second, options


def test_all_pages_are_bound_into_collection_and_scheduler_proof(tmp_path, monkeypatch):
    root, first, second, options = setup(tmp_path)
    result = collect(root, **options)
    assert result["search_complete"] and result["undiscovered_results"] == 0
    assert [item["path"] for item in result["outcomes"]] == [ID, OTHER]
    bundle, digest, hits = CatalogProof("KB9999991").saved_index(
        tmp_path, "synthetic", root.name
    )
    assert bundle == root and digest == result["search_fingerprint"]
    assert len(hits) == 2
    assert digest != hashlib.sha256(first).hexdigest()

    def denied(*a, **k):
        raise AssertionError("Replay made a network request")

    monkeypatch.setattr("http.client.HTTPSConnection", denied)
    replay = collect(
        root,
        kb="KB9999991",
        origin="synthetic",
        execution_id=root.name,
        replay_only=True,
    )
    assert replay == result


def test_page_budget_preserves_incomplete_search(tmp_path):
    root, first, second, options = setup(tmp_path)
    result = collect(root, **options, page_limit=1)
    assert not result["search_complete"] and result["undiscovered_results"] == 1
    assert not (root / "page-2").exists()
    with pytest.raises(ValueError, match="incomplete"):
        CatalogProof("KB9999991").saved_index(tmp_path, "synthetic", root.name)


@pytest.mark.parametrize(
    "damage",
    ["bytes", "receipt", "request", "missing", "gap", "symlink", "clock", "wrong_page"],
)
def test_saved_chain_tampering_or_interruption_rejects(tmp_path, damage):
    root, first, second, options = setup(tmp_path)
    collect(root, **options)
    directory = root / "page-2"
    if damage == "bytes":
        (directory / "search.html").write_bytes(b"changed")
    elif damage in ("receipt", "request"):
        file = directory / f"{damage}.json"
        value = json.loads(file.read_text())
        value["previous_fingerprint"] = "0" * 64
        file.write_text(json.dumps(value))
    elif damage == "missing":
        (directory / "receipt.json").unlink()
    elif damage == "gap":
        directory.rename(root / "page-3")
    elif damage == "symlink":
        directory.rename(root / "elsewhere")
        directory.symlink_to(root / "elsewhere", target_is_directory=True)
    elif damage == "clock":
        file = directory / "receipt.json"
        value = json.loads(file.read_text())
        value["collected_at"] = "2026-09-16T00:00:00"
        file.write_text(json.dumps(value))
    else:
        (directory / "search.html").write_bytes(first)
        file = directory / "receipt.json"
        value = json.loads(file.read_text())
        value["fingerprint"] = hashlib.sha256(first).hexdigest()
        file.write_text(json.dumps(value))
    with pytest.raises((ValueError, OSError)):
        CatalogProof("KB9999991").saved_index(tmp_path, "synthetic", root.name)


def test_failed_page_request_is_not_automatically_retried(tmp_path):
    tmp_path.chmod(0o700)
    first = payload(count="1 - 1 of 2 (page 1 of 2)")
    request = dict(
        origin="public", execution_id=str(uuid4()), source_url=search_url("KB9999991")
    )
    calls = []

    def download(url):
        calls.append(url)
        raise ValueError("Synthetic transport interruption")

    args = dict(request=request, kb="KB9999991", first_payload=first, download=download)
    with pytest.raises(ValueError, match="interruption"):
        saved_pages(tmp_path, **args)
    with pytest.raises(FileNotFoundError):
        saved_pages(tmp_path, **args)
    assert calls == [search_url("KB9999991", page=2)]


@pytest.mark.parametrize("limit", [0, 101, True, "3"])
def test_invalid_page_budget_has_no_collection_effect(tmp_path, limit):
    root, first, second, options = setup(tmp_path)
    with pytest.raises(ValueError):
        collect(root, **options, page_limit=limit)
    assert not root.exists()


def test_fixture_membership_includes_all_pages_and_rejects_gaps():
    from standalone.operations.catalog_worker import fixture_data

    first = payload(count="1 - 1 of 2 (page 1 of 2)")
    second = payload(row(OTHER), count="2 - 2 of 2 (page 2 of 2)")
    document = dict(
        index=first.decode(),
        pages={"2": second.decode()},
        records={OTHER: "synthetic detail"},
    )
    index, records, pages = fixture_data(document, "KB9999991")
    assert index == first and pages == {2: second} and OTHER in records
    for mutation in [
        dict(pages={"3": second.decode()}),
        dict(pages=[]),
        dict(pages={"02": second.decode()}),
        dict(extra="unknown"),
    ]:
        with pytest.raises(ValueError):
            fixture_data(dict(document, **mutation), "KB9999991")
