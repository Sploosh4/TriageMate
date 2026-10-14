"""Explicit refusal for deferred OSV collection; retained parsing lives in parsing.osv_query."""


def _page(request, deadline):
    """Retired collector; original source/tests are preserved in the archive tag."""
    from standalone.evidence_pipeline.collection.collection_scope import (
        require_active_collection,
    )

    require_active_collection("OSV")


def collect(
    *, scope, name=None, ecosystem=None, purl=None, version=None, on_response=None
):
    """Retired collector; original source/tests are preserved in the archive tag."""
    from standalone.evidence_pipeline.collection.collection_scope import (
        require_active_collection,
    )

    require_active_collection("OSV")
