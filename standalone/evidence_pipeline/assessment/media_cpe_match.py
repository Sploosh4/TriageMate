"""Media CPE conditions require the established collected package/manifest identity."""

from standalone.evidence_pipeline.assessment.media_inventory_match import (
    MEDIA_PRODUCTS,
    evaluate_media,
)
from standalone.evidence_pipeline.assessment.windows_app_cpe_match import (
    evaluate_application_criterion,
)
from standalone.evidence_pipeline.assessment.windows_cpe_match import (
    evaluate_boolean_configurations,
)


def evaluate_configurations(configurations, facts):
    # This exact outcome is reached only after inventory identity, installation,
    # manifest, Windows platform and four-component version checks succeed.
    identity = evaluate_media(None, provider="microsoft", facts=facts)
    if identity["reason"] != "missing_published_microsoft_cna_evidence":
        return dict(state="unknown", reason="missing_supported_media_identity")
    return evaluate_boolean_configurations(
        configurations,
        lambda item: evaluate_application_criterion(
            item,
            facts,
            product=facts["product"],
            cpe_product=MEDIA_PRODUCTS[facts["product"]][1],
        ),
        reason="evaluated_media_cpe_conditions",
    )
