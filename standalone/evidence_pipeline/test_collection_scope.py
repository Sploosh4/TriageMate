"""Deferred inputs cannot collect via retained metadata, APIs or scheduling."""

from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
import inspect

import pytest

from standalone.evidence_pipeline.collection.collection_scope import DEFERRED_SOURCES
from .contracts import SourceScope
from standalone.evidence_pipeline.collection import public_collection, public_transport
from standalone.evidence_pipeline.parsing.public_snapshot import PARSERS
from standalone.operations.process_worker import PublicRecipe
from standalone.operations.dispatch import Job


@pytest.fixture
def no_network(monkeypatch):
    def fail(*args, **kwargs):
        pytest.fail("Deferred source attempted network I/O")

    monkeypatch.setattr(public_transport, "_download_url", fail)
    monkeypatch.setattr(public_collection, "download", fail)
    monkeypatch.setattr(public_transport.http.client, "HTTPSConnection", fail)


def chosen(source, kind):
    return SourceScope(
        str(uuid4()),
        source,
        kind,
        "https://example.invalid/deferred",
        "synthetic",
        "Explicit synthetic deferral regression",
    )


@pytest.mark.parametrize("source", sorted(DEFERRED_SOURCES))
def test_deferred_metadata_cannot_enable_collection(source, tmp_path, no_network):
    pairs = [pair for pair in PARSERS if pair[0] == source]
    assert pairs, "Retained parser identity must remain inspectable"
    for _, kind in pairs:
        scope = chosen(source, kind)
        with pytest.raises(ValueError, match="deferred"):
            public_collection.prepare(
                scope, str(uuid4()), tmp_path / "bundle", synthetic_payload=b"{}"
            )
        with pytest.raises(ValueError, match="deferred"):
            public_transport.download(source, input_kind=kind)
        with pytest.raises(ValueError, match="deferred"):
            public_transport.download_vendor(replace(scope, origin="public"))
        now = datetime.now(timezone.utc)
        job = Job(str(uuid4()), scope.connection_id, now, now, ())
        with pytest.raises(ValueError, match="deferred"):
            PublicRecipe(
                scope, tmp_path / "bundle", Path("/synthetic-fixture")
            ).validate(job)
    assert not (tmp_path / "bundle").exists()


@pytest.mark.parametrize("source", ["GitHub", "Ubuntu"])
def test_deferred_repository_transport_rejects_before_http(source, no_network):
    with pytest.raises(ValueError, match="deferred"):
        public_transport.download_github_object("ref", "heads/main", source=source)


@pytest.mark.parametrize("source", ["GitHub", "Ubuntu"])
@pytest.mark.parametrize("replay_only", [False, True])
def test_deferred_repository_scans_reject_before_creating_state(
    source, replay_only, tmp_path, no_network
):
    from standalone.evidence_pipeline.collection.github_scan import scan, scan_current

    bundle = tmp_path / "bundle"
    options = dict(source=source, origin="public", replay_only=replay_only)
    with pytest.raises(ValueError, match="deferred"):
        scan("a" * 40, bundle, **options)
    with pytest.raises(ValueError, match="deferred"):
        scan_current(bundle, **options)
    assert not bundle.exists()


def test_historical_epss_rejected_current_route_preserved(tmp_path, no_network):
    scope = chosen("FIRST", "epss")
    with pytest.raises(ValueError, match="deferred"):
        public_collection.prepare(
            scope, str(uuid4()), tmp_path / "archive", score_date="2026-09-12"
        )
    with pytest.raises(ValueError, match="deferred"):
        public_transport.download("FIRST", score_date="2026-09-12")
    assert public_transport.endpoint("FIRST").endswith("epss_scores-current.csv.gz")
    assert not (tmp_path / "archive").exists()


@pytest.mark.parametrize(
    "module,name",
    [
        ("github_repository", "collect"),
        ("github_repository", "collect_current"),
        ("cisco_collection", "collect"),
        ("cisco_rss_collection", "prepare"),
        ("redhat_collection", "collect"),
        ("osv_query_collection", "prepare"),
        ("osv_query", "collect"),
        ("osv_query", "_page"),
        ("ubuntu_upstream", "collect"),
        ("ubuntu_upstream", "collect_tree"),
        ("ubuntu_upstream", "_collect_target"),
    ],
)
def test_retired_entry_points_have_no_collector_body(module, name, no_network):
    import importlib

    fn = getattr(importlib.import_module(".collection." + module, __package__), name)
    args = {
        key: None
        for key, param in inspect.signature(fn).parameters.items()
        if param.default is inspect.Parameter.empty
    }
    with pytest.raises(ValueError, match="deferred"):
        fn(**args)


ACTIVE_URLS = [
    (
        "FIRST",
        "epss",
        {},
        "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
    ),
    (
        "CISA",
        "kev",
        {},
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    ),
    (
        "NVD",
        "vulnerabilities",
        {"cve": "CVE-2099-12345"},
        "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2099-12345",
    ),
    (
        "CVE",
        "records",
        {"cve": "CVE-2099-12345"},
        "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2099/12xxx/CVE-2099-12345.json",
    ),
    (
        "CISA",
        "vulnrichment",
        {"cve": "CVE-2099-12345"},
        "https://raw.githubusercontent.com/cisagov/vulnrichment/develop/2099/12xxx/CVE-2099-12345.json",
    ),
]


def assert_active_route(source, kind, parameters, expected, monkeypatch):
    urls = []
    monkeypatch.setattr(
        public_transport, "_download_url", lambda url, **kw: urls.append(url)
    )
    public_transport.download(source, input_kind=kind, **parameters)
    assert urls == [expected]


@pytest.mark.parametrize("source,kind,parameters,expected", ACTIVE_URLS)
def test_active_transport_still_reaches_its_fixed_url(
    source, kind, parameters, expected, monkeypatch
):
    assert_active_route(source, kind, parameters, expected, monkeypatch)


@pytest.mark.parametrize(
    "wrong",
    [
        "https://incorrect.example.invalid/rest/json/cves/2.0?cveId=CVE-2099-12345",
        "https://services.nvd.nist.gov/wrong?cveId=CVE-2099-12345",
        "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2099-99999",
    ],
)
def test_route_assertion_rejects_incorrect_publisher_path_and_cve(monkeypatch, wrong):
    monkeypatch.setattr(public_transport, "endpoint", lambda *args, **kwargs: wrong)
    with pytest.raises(AssertionError):
        assert_active_route(*ACTIVE_URLS[2], monkeypatch)
