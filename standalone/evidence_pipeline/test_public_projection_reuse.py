"""Exact reused projections retain the generic public corruption checks."""

import json
from decimal import Decimal

import pytest

from standalone.evidence_pipeline.persistence import (
    cve_attribution,
    cvrf_attribution,
    osv_attribution,
    reference_attribution,
)
from standalone.evidence_pipeline.persistence import public_attribution
from standalone.evidence_pipeline.parsing.devices import stable_id
from .verification_spool import VerificationSpool


@pytest.mark.parametrize(
    "damage",
    [None, "missing", "extra", "numeric", "unexpected-field", "wrong-receipt"],
)
def test_reused_public_projection_checks_every_row_and_exact_value(monkeypatch, damage):
    # Isolate this generic projection check from the independently tested MSRC,
    # CVE and OSV inventories. No SQL re-read may replace the supplied snapshot.
    for module, name in (
        (cvrf_attribution, "verify_update_inventory"),
        (cve_attribution, "verify_cve_inventory"),
        (osv_attribution, "verify_osv_inventory"),
        (reference_attribution, "verify_reference_inventory"),
    ):
        monkeypatch.setattr(module, name, lambda *args: None)
    monkeypatch.setattr(
        public_attribution,
        "revision_ordered_receipts",
        lambda cursor, receipts: iter(receipts.values()),
    )
    receipt_id = "synthetic-receipt"
    revision_id = "synthetic-revision"
    cve = "CVE-2026-999999"
    table = "epss_observations"
    identity = stable_id("public-observation", receipt_id, table, "0")
    probability = Decimal("0.12345678901234567890123456789")
    observation = {
        "id": identity,
        "cve_id": cve,
        "receipt_id": receipt_id,
        "probability": probability,
        "percentile": Decimal(0),
        "score_date": "2026-09-19",
        "model_version": None,
    }
    observations = [observation]
    if damage == "missing":
        observations = []
    elif damage == "extra":
        observations.append({**observation, "id": "synthetic-extra"})
    elif damage == "numeric":
        observation["probability"] += Decimal("0.00000000000000000000000000001")
    elif damage == "unexpected-field":
        observation["model_version"] = "not-in-source"
    elif damage == "wrong-receipt":
        observation["receipt_id"] = "synthetic-other-receipt"
    claim = json.dumps(
        {
            "record": {"cve_id": cve},
            "projection": [
                [
                    table,
                    {
                        "probability": {"decimal": str(probability)},
                        "percentile": {"decimal": "0"},
                        "score_date": {"iso": "2026-09-19"},
                    },
                ]
            ],
        }
    )
    with VerificationSpool() as spool:
        extras = {
            name: spool.rows(observations if name == table else [])
            for name in public_attribution.PUBLIC_PROJECTION_TABLES
        }
        explained = {name: set() for name in (*extras, "vulnerabilities")}
        revisions = spool.mapping(
            [
                (
                    revision_id,
                    {
                        "id": revision_id,
                        "source_record_id": cve,
                        "connection_id": "synthetic-source",
                    },
                )
            ]
        )
        receipts = spool.mapping(
            [(receipt_id, {"id": receipt_id, "source_revision_id": revision_id})]
        )
        verified = []

        def run():
            public_attribution._verify_public(
                None,
                extras,
                {
                    "synthetic-source": {
                        "source_name": "FIRST",
                        "input_kind": "epss",
                        "tenant_id": None,
                    }
                },
                revisions,
                receipts,
                explained,
                lambda *args: verified.append(args),
                {revision_id: claim},
                spool,
                None,
            )

        if damage:
            with pytest.raises(AssertionError, match="projection|observation"):
                run()
        else:
            run()
            assert explained[table] == {identity}
            assert explained["vulnerabilities"] == {cve}
            assert verified[0][0:2] == (receipt_id, cve)
            assert len(verified) == 1
