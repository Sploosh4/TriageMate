from pydantic import BaseModel, Field
from typing import Optional


def camel_case(s: str) -> str:
    """Convert snake_case to camelCase for API responses."""
    parts = s.split("_")
    return parts[0] + "".join(p.capitalize() for p in parts[1:])


class BaseModelConfig(BaseModel):
    model_config = {
        "alias_generator": camel_case,
        "populate_by_name": True,
        "protected_namespaces": (),
    }


class MitreTechnique(BaseModelConfig):
    id: str
    name: str
    desc: str


class ScoringWeight(BaseModelConfig):
    name: str
    awarded: int
    max: int
    justification: str
    is_substituted: bool = False


class AssetRegistryEntry(BaseModelConfig):
    label: str
    value: str


class SubstitutionBlock(BaseModelConfig):
    original_epss: str
    substituted_epss: str
    model_confidence: str
    reason: str


class CaseViewData(BaseModelConfig):
    summary_paragraphs: list[str]
    mission_prevalence: list[str]
    mitre_techniques: list[MitreTechnique]
    text_conflict: bool
    text_conflict_note: str
    scanner_output: str
    weakness_template: str
    advisory_ref_id: str
    advisory_quote: str
    investigation_notes: str
    has_substitution: bool
    substitution_block: Optional[SubstitutionBlock] = None
    score_gauge_value: int
    score_gauge_band: str
    gauge_band_colour: str
    scoring_weights: list[ScoringWeight]
    asset_registry: list[AssetRegistryEntry]
    nvd_freshness: int = -1


class QueueRow(BaseModelConfig):
    id: int
    vulnerability_id: str
    hostname: str
    priority_score: int
    risk_band: str
    detection_reason: str
    tier: str
    compliance: str
    compliance_category: int
    interface_type: str = ""
    created_at: str = ""


class QueueResponse(BaseModelConfig):
    rows: list[QueueRow]


class CaseResponse(BaseModelConfig):
    queue_row: QueueRow
    case_view: CaseViewData
    trace_output: Optional[dict] = Field(default=None, alias="_trace")


class MetricsResponse(BaseModelConfig):
    critical_actions: int
    low_confidence: int
    exposed: int
    needs_human_validation: int


class IngestRequest(BaseModelConfig):
    vulnerability_id: str
    hostname: str
    cvss_score: float
    cvss_vector: Optional[str] = None
    cisa_kev: bool = False
    epss_score: Optional[float] = None
    target_ip: str = ""
    raw_description: str = ""
    scanner_output_raw: str = ""
    weakness_template_raw: str = ""
    exploit_maturity: int = 0
    has_public_poc: bool = False
    vendor_patch_status: int = 0


class TriageConflictResult(BaseModel):
    """Schema for structured LLM output in Tier 2 force-reflection analysis.

    All fields are required (no Optional/Union) to maintain compatibility
    with Anthropic's JSON Schema subset which does not support anyOf/oneOf.
    """

    text_conflict: bool
    conflict_note: str
    rag_result: str
    resolution: str
    confidence: float
    score_adjustment: int


# ── Auth models ───────────────────────────────────────────────────────────


class LoginRequest(BaseModelConfig):
    """Login payload: username + password."""

    username: str
    password: str


class TokenResponse(BaseModelConfig):
    """JWT token response returned by login and refresh endpoints."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModelConfig):
    """Refresh request payload: the refresh token."""

    refresh_token: str


class ReviewRequest(BaseModelConfig):
    analyst_decision: str
    override_score: int | None = None
    override_band: str | None = None
    notes: str = ""
    analyst_name: str


class ReviewQueueItem(BaseModelConfig):
    id: int
    vulnerability_id: str
    hostname: str
    priority_score: int
    risk_band: str
    detection_tier: str
    review_status: str | None = None
    flagged_for_review: bool = False
    tier_2_text_conflict: bool = False
    created_at: str = ""


class ReviewQueueResponse(BaseModelConfig):
    rows: list[ReviewQueueItem]
    total: int


class DriftMetricsResponse(BaseModelConfig):
    score_trend: list[dict]
    tier_routing: dict
    risk_band_distribution: dict
    detection_tier_trend: list[dict]
    feature_drift: dict
    total_audited: int


class MlDriftFeature(BaseModelConfig):
    psi: float
    status: str


class MlDriftResponse(BaseModelConfig):
    features: dict[str, MlDriftFeature]
    composite_psi: float
    status: str
    total_samples: int
