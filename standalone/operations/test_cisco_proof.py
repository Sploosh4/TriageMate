"""Scheduler acceptance binds every exact RSS member to its committed receipt."""

from uuid import uuid4

from standalone.evidence_pipeline.collection.cisco_collection import collect
from standalone.evidence_pipeline.test_cisco_collection import fixtures


def saved(tmp_path):
    index, documents = fixtures(("cisco-sa-synthetic-AbC",))
    run = str(uuid4())
    collect(
        tmp_path / run,
        origin="synthetic",
        execution_id=run,
        synthetic_index=index,
        synthetic_payloads=documents,
    )
    return run
