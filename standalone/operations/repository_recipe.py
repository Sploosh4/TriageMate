"""Explicit repository configuration and bounded synthetic fixture loading."""

from dataclasses import dataclass
import json
from pathlib import Path

from standalone.evidence_pipeline.contracts import (
    SourceScope,
    identifier,
)
from standalone.evidence_pipeline.collection.snapshot_bundle import (
    _private_directory,
    _read,
)
from standalone.evidence_pipeline.parsing.redhat_discovery import INDEX_URL
from standalone.evidence_pipeline.parsing.cisco_rss import FEED_URL as CISCO_FEED_URL

from .repository_worker import collect_batch


REPOSITORIES = {
    "GitHub": "github/advisory-database",
    "CVE": "CVEProject/cvelistV5",
    "CISA": "cisagov/vulnrichment",
    "Ubuntu": "canonical/ubuntu-security-notices",
    "WA SOC": "wagov/wasocshared",
}

SOURCE_URLS = {
    **{
        source: "https://github.com/" + repository
        for source, repository in REPOSITORIES.items()
    },
    "Red Hat": INDEX_URL,
    "MSRC": "https://api.msrc.microsoft.com/cvrf/v3.0/updates",
    "Cisco": CISCO_FEED_URL,
    "Microsoft Update Catalog": "https://www.catalog.update.microsoft.com/Search.aspx",
}


def source_reference(binding):
    if not isinstance(binding, dict):
        raise ValueError("Invalid discovery source binding")
    catalog = binding.get("source") == "Microsoft Update Catalog"
    if catalog and set(binding) == {"source", "origin", "mode"}:
        if (
            binding["origin"] not in {"synthetic", "public"}
            or binding["mode"] != "targets"
        ):
            raise ValueError("Invalid Catalog target notification scope")
        return "triagemate:catalog/missing-patches"
    if (
        set(binding)
        != ({"source", "origin", "kb"} if catalog else {"source", "origin"})
        or binding.get("source") not in SOURCE_URLS
        or binding.get("origin") not in {"synthetic", "public"}
    ):
        raise ValueError("Invalid discovery source binding")
    if catalog:
        from standalone.evidence_pipeline.parsing.catalog_discovery import search_url

        return search_url(binding["kb"])
    return SOURCE_URLS[binding["source"]]


def fixtures(path):
    from .configuration import unique_fields
    from .checkpoint import keys

    document = json.loads(_read(path), object_pairs_hook=unique_fields)
    keys(document, ["origin", "objects", "records"])
    if (
        document["origin"] != "synthetic"
        or not isinstance(document["objects"], list)
        or not isinstance(document["records"], dict)
    ):
        raise ValueError("Explicit synthetic repository fixture required")
    objects = {}
    for item in document["objects"]:
        keys(item, ["kind", "identity", "payload"])
        if (
            item["kind"] not in ("ref", "commits", "trees")
            or not isinstance(item["identity"], str)
            or not isinstance(item["payload"], str)
        ):
            raise ValueError("Invalid synthetic repository object")
        key = item["kind"], item["identity"]
        if key in objects:
            raise ValueError("Duplicate synthetic repository object")
        objects[key] = item["payload"].encode()
    if any(not isinstance(value, str) for value in document["records"].values()):
        raise ValueError("Synthetic repository records require exact wire text")
    return objects, {key: value.encode() for key, value in document["records"].items()}


@dataclass(frozen=True)
class RepositoryRecipe:
    scope: SourceScope
    bundle_root: Path
    synthetic_input: Path | None = None
    allow_network: bool = False
    metadata_limit: int = 10
    record_limit: int = 100
    pass_limit: int = 10000
    kb: str | None = None
    starting_month: str | None = None
    retained_ids: frozenset[str] = frozenset()

    def validate(self, job):
        from standalone.evidence_pipeline.collection.collection_scope import (
            require_active_collection,
        )

        if not isinstance(self.scope, SourceScope):
            raise ValueError("Invalid scheduled repository scope")
        require_active_collection(self.scope.source)
        if self.scope.source == "MSRC":
            from .msrc_proof import MsrcProof

            MsrcProof(self.starting_month, self.retained_ids)
        elif self.starting_month is not None or self.retained_ids:
            raise ValueError("Publication range applies only to MSRC discovery")
        catalog = self.scope.source == "Microsoft Update Catalog"
        expected = SOURCE_URLS.get(self.scope.source)
        if catalog:
            from standalone.evidence_pipeline.parsing.catalog_discovery import (
                search_url,
            )

            expected = search_url(self.kb)
        elif self.kb is not None:
            raise ValueError("KB parameters apply only to Catalog discovery")
        if (
            not isinstance(self.scope, SourceScope)
            or self.scope.source not in SOURCE_URLS
            or self.scope.input_kind != ("catalog_search" if catalog else "repository")
            or self.scope.tenant_id is not None
            or self.scope.scope_reference != expected
            or self.scope.connection_id != identifier(job.input_id)
            or job.prerequisite_snapshots
        ):
            raise ValueError("Invalid scheduled repository scope")
        identifier(job.run_id)
        if type(self.allow_network) is not bool:
            raise ValueError("Explicit repository network authority required")
        if self.scope.origin == "synthetic":
            if self.synthetic_input is None or self.allow_network:
                raise ValueError("Synthetic repository requires offline fixture")
        elif (
            self.scope.origin != "public"
            or not self.allow_network
            or self.synthetic_input is not None
        ):
            raise ValueError("Public repository requires explicit network opt-in")
        for path in (self.bundle_root, self.synthetic_input):
            if path is not None and (
                not isinstance(path, Path) or not path.is_absolute()
            ):
                raise ValueError("Repository paths must be absolute")
        for value, maximum in (
            (self.metadata_limit, 100),
            (self.record_limit, 100),
            (self.pass_limit, 100 if catalog else 10000),
        ):
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError("Invalid scheduled repository budget")
        _private_directory(self.bundle_root)

    def collect(self, job, service_key=None):
        self.validate(job)
        if self.scope.source == "MSRC":
            from .msrc_worker import (
                collect_batch as collect_msrc,
                fixtures as msrc_fixtures,
            )
            from .msrc_proof import MsrcProof

            index, records = (
                (None, None)
                if self.synthetic_input is None
                else msrc_fixtures(self.synthetic_input)
            )
            result = collect_msrc(
                self.bundle_root,
                origin=self.scope.origin,
                execution_id=job.run_id,
                starting_month=self.starting_month,
                retained_ids=self.retained_ids,
                allow_network=self.allow_network,
                synthetic_index=index,
                synthetic_payloads=records,
                record_limit=self.record_limit,
                pass_limit=self.pass_limit,
            )
            if result.reason == "finished":
                MsrcProof(self.starting_month, self.retained_ids).seal(
                    service_key, job, self.scope.origin, self.bundle_root
                )
            return result
        if self.scope.source == "Cisco":
            from .cisco_worker import (
                collect_batch as collect_cisco,
                fixtures as cisco_fixtures,
            )
            from .cisco_proof import CiscoProof

            index, records = (
                (None, None)
                if self.synthetic_input is None
                else cisco_fixtures(self.synthetic_input)
            )
            result = collect_cisco(
                self.bundle_root,
                origin=self.scope.origin,
                execution_id=job.run_id,
                allow_network=self.allow_network,
                synthetic_index=index,
                synthetic_payloads=records,
                record_limit=self.record_limit,
                pass_limit=self.pass_limit,
            )
            if result.reason == "finished":
                CiscoProof().seal(service_key, job, self.scope.origin, self.bundle_root)
            return result
        if self.scope.source == "Microsoft Update Catalog":
            from .catalog_worker import (
                collect_batch as collect_catalog,
                fixtures as catalog_fixtures,
            )
            from .catalog_proof import CatalogProof

            index, records, pages = (
                (None, None, None)
                if self.synthetic_input is None
                else catalog_fixtures(self.synthetic_input, self.kb)
            )
            result = collect_catalog(
                self.bundle_root,
                origin=self.scope.origin,
                kb=self.kb,
                execution_id=job.run_id,
                allow_network=self.allow_network,
                synthetic_index=index,
                synthetic_payloads=records,
                synthetic_pages=pages,
                record_limit=self.record_limit,
                pass_limit=self.pass_limit,
            )
            if result.reason == "finished":
                CatalogProof(self.kb).seal(
                    service_key, job, self.scope.origin, self.bundle_root
                )
            return result
        if self.scope.source == "Red Hat":
            from .redhat_worker import (
                collect_batch as collect_redhat,
                fixtures as redhat_fixtures,
            )
            from .redhat_proof import seal

            index, records = (
                (None, None)
                if self.synthetic_input is None
                else redhat_fixtures(self.synthetic_input)
            )
            result = collect_redhat(
                self.bundle_root,
                origin=self.scope.origin,
                execution_id=job.run_id,
                allow_network=self.allow_network,
                synthetic_index=index,
                synthetic_payloads=records,
                record_limit=self.record_limit,
                pass_limit=self.pass_limit,
            )
            if result.reason == "finished":
                seal(service_key, job, self.scope.origin, self.bundle_root)
            return result
        objects, records = (
            (None, None)
            if self.synthetic_input is None
            else fixtures(self.synthetic_input)
        )
        return collect_batch(
            self.scope.source,
            self.bundle_root,
            origin=self.scope.origin,
            execution_id=job.run_id,
            allow_network=self.allow_network,
            synthetic_objects=objects,
            synthetic_payloads=records,
            metadata_limit=self.metadata_limit,
            record_limit=self.record_limit,
            pass_limit=self.pass_limit,
        )
