from pydantic import BaseModel, Field
from typing import Optional
from datetime import date


def camel_case(s: str) -> str:
    """Convert snake_case to camelCase for API responses."""
    parts = s.split('_')
    return parts[0] + ''.join(p.capitalize() for p in parts[1:])


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


class QueueResponse(BaseModelConfig):
    rows: list[QueueRow]


class CaseResponse(BaseModelConfig):
    queue_row: QueueRow
    case_view: CaseViewData


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
    epss_score: float = 0.0
    target_ip: str = ""
    raw_description: str = ""
